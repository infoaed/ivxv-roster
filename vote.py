#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2025 Kaspar Kartanas
# Copyright (C) 2025-2026 Märt Põder

import subprocess
import urllib.parse
import re
import getpass
import hashlib
import json
import os
import base64
import qrcode
import argparse
import io
import uuid
from tinyec import registry
from pyivxv.crypto.keys import PublicKey
from pyasice import Container


ap = argparse.ArgumentParser()
ap.add_argument("--key", "-k", default="./DUMMY_pub.pem", 
                help="Hääletuse avaliku võtme fail")
ap.add_argument("--message", "-m", default="", help="Valiku kood, tüüpiliselt kujul 0000.000")
ap.add_argument("--ballot", "-b", default="", help="Balloti fail ehk sedel ise")
ap.add_argument("--ephemeral", "-e", default="", help="Efemeerse võtme väärtus base64 vormingus")
ap.add_argument("--pin1", default="", help="Isikutuvastuse PIN1 väärtus, puudumisel küsitakse")
ap.add_argument("--pin2", default="", help="Allkirjastamise PIN2 väärtus, puudumisel küsitakse(ei tööta)")
ap.add_argument("--local", "-l", default=False, action='store_true', help="Täna serveriga juttu ei tee")
ap.add_argument("--collector", "-c", default=False, action='store_true', help="Ajatemplile kogumisteenuse signatuur")
ap.add_argument("--round", "-r", default='DUMMY', help="Valimiste identifikaator")
ap.add_argument("--question", "-q", default='DUMMY', help="Küsimuse identifikaator")
args = ap.parse_args()

#args.ballot = "CIn4xUjgTNlEtlbdlYtzLQ==.ballot"
#args.ephemeral = "m4/xSUTr1dK+ur4vpvMmThj3BFvJTVGdCdUf0rNrQ7aR6Yyp4YHr4UbQX9sQZdki"

save_pin1=args.pin1
ballot_file=args.ballot


def get_slots_info():
    """
    Tagastab nimekirja slotiinfo sõnastikest.
    Iga sõnastik sisaldab: slot, token label, manufacturer, model, serial num, flags, pin min/max jne.
    """
    cmd = f'pkcs11-tool -L'
    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    output = result.stdout.strip()

    # Eemalda esimene rida "Available slots:" kui see on olemas
    output = re.sub(r'^Available slots:\s*\n?', '', output)

    # Jagame slotid plokkideks: iga "Slot N (...)" algusega
    slot_blocks = re.split(r'(?=Slot \d+)', output)
    slots = []

    for block in slot_blocks:
        block = block.strip()
        if not block:
            continue

        info = {}
        # Võtame välja peamised väljad (kõik, mis on kujul "nimi : väärtus")
        for line in block.splitlines():
            if ':' in line:
                key, value = [x.strip() for x in line.split(':', 1)]
                info[key] = value

        # Lisa kogu plokk tekstina ka, et oleks lihtne hiljem uuesti kontrollida
        info["_raw"] = block
        slots.append(info)

    return slots

def find_slot_by_label(slots, search_text):
    """
    Tagastab esimese sloti, mille token label sisaldab otsitavat teksti.
    :param slots: get_slots_info() väljund
    :param search_text: tekst, mida otsida (nt "PIN1" või "PIN2")
    :return: sloti info dict või None
    """
    search_text = search_text.lower()
    for slot in slots:
        label = slot.get("token label", "").lower()
        if search_text in label:
            return slot
    return None

# Funktsioon TLS päringu saatmiseks
def send_vote_tls_request(json_obj, token, cert_path):
    # Muutame JSON stringiks
    json_data = json.dumps(json_obj)
    token_enc = urllib.parse.quote(token, safe='')
    global save_pin1
    if save_pin1: 
        PIN1 = save_pin1
    else:
        save_pin1 = getpass.getpass("Sisesta PIN1: ")
        PIN1 = save_pin1

    # OpenSSL käsk
    cmd = [
        "openssl", "s_client",
        "-tls1_2",
        "-ign_eof",
        "-connect", "koguja1.valimised.ee:443",
        "-servername", "voting.ivxv.valimised.ee",
        "-engine", "pkcs11",
        "-keyform", "ENGINE",
        "-key", f'pkcs11:type=private;token={token_enc};pin-value={PIN1}',
        "-cert", cert_path
    ]

    #print(" ".join(a for a in cmd))
    # Käivitame OpenSSL-i ja saadame JSON-i stdin-i
    result = subprocess.run(cmd, input=json_data.encode(), capture_output=True)

    # Tagastame serveri vastuse
    return result.stdout.decode(errors="ignore"), result.stderr.decode(errors="ignore")

def export_cert_to_pem(pem_path="./cert.pem", cert_id="01"):
    """
    Ekspordib PKCS#11 abil kiipkaardilt sertifikaadi PEM formaadis failiasukohta.
    """
    # Veendu, et kataloog olemas
    os.makedirs(os.path.dirname(pem_path), exist_ok=True)

    # Käivita pkcs11-tool sertifikaadi eksportimiseks kiipkaardilt
    cmd1 = [
        "pkcs11-tool",
        "-r",              # read-only
        "-y", "cert",      # sertifikaat
        "-o", f"{pem_path}.der",    # väljundfail
        "--id", cert_id    # sertifikaadi ID
    ]
    # Konverdi pem formaati
    cmd2 = [
        "openssl",
        "x509",
        "-inform", "DER",               # vorming
        "-in", f"{pem_path}.der",       # sisendfail
        "-out", f"{pem_path}"           # väljundfail
    ]
    try:
        subprocess.run(cmd1, check=True)# loe kiibist
        subprocess.run(cmd2, check=True)# vorminda 
        os.remove(f"{pem_path}.der")    # kustuta ajutine der fail
        print(f"Sertifikaat edukalt loodud: {pem_path}")
        return pem_path
    except subprocess.CalledProcessError as e:
        print(f"Sertifikaadi loomine ebaõnnestus: {e}")
        return None

def parse_vote_response(out):
    json_start = out.find('{')
    json_end = out.rfind('}') + 1  # +1, et sulg kaasa võtta
    if json_start == -1 or json_end == -1:
        raise ValueError("JSONi ei leitud serveri väljundist")
    json_text = out[json_start:json_end]
    data = json.loads(json_text)
    if data["error"]:
        return data
    data["result"]["Qualification"]["ocsp_"] = base64.b64decode(data["result"]["Qualification"]["ocsp"])
    data["result"]["Qualification"]["tspreg_"] = base64.b64decode(data["result"]["Qualification"]["tspreg"])
    return data

def make_qr(sessid="06b5f96b8f70309749905fac7c42cd13", 
            ephkey="B3kUQBwMeA/ZcNVFVEPcA2GbOFlR7vmt46mYiXZfejyEw7/J5JcGCgnqx8vWSl4B", 
            voteid="mhg7woPfCKhO6HAMABIQtQ==",
            filename="qr.png"
            ):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    data = f"""{sessid}
{ephkey}
{voteid}"""
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(filename)
    return img

def parse_choices_response(out):
    json_start = out.find('{')
    json_end = out.rfind('}') + 1  # +1, et sulg kaasa võtta
    if json_start == -1 or json_end == -1:
        raise ValueError("JSONi ei leitud serveri väljundist")
    json_text = out[json_start:json_end]
    data = json.loads(json_text)

    data["result"]["List_"] = json.loads(base64.b64decode(data["result"]["List"]).decode())
    return data

# Funktsioon TLS päringu saatmiseks
def send_choices_request(json_obj, token, cert_path):
    # Muutame JSON stringiks
    json_data = json.dumps(json_obj)
    token_enc = urllib.parse.quote(token, safe='')
    global save_pin1
    if save_pin1: 
        PIN1 = save_pin1
    else:
        save_pin1 = getpass.getpass("Sisesta PIN1: ")
        PIN1 = save_pin1

    # OpenSSL käsk
    cmd = [
        "openssl", "s_client",
        "-tls1_2",
        "-ign_eof",
        "-connect", "koguja1.valimised.ee:443",
        "-servername", "choices.ivxv.valimised.ee",
        "-engine", "pkcs11",
        "-keyform", "ENGINE",
        "-key", f'pkcs11:type=private;token={token_enc};pin-value={PIN1}',
        "-cert", cert_path
    ]

    #print(" ".join(a for a in cmd))
    # Käivitame OpenSSL-i ja saadame JSON-i stdin-i
    result = subprocess.run(cmd, input=json_data.encode(), capture_output=True)

    # Tagastame serveri vastuse
    return result.stdout.decode(errors="ignore"), result.stderr.decode(errors="ignore")

def pick_choice(List_):
    print("Sisestad sedeli teksti ise? (jah)/ei): vaikimisi jah")
    if input().strip().lower() == "ei":
        # vali erakond/valimisliit/nimekiri

        grupid = list(List_.keys())
        print("Vali nimekiri:")
        for i, g in enumerate(grupid, 1):
            print(f"{i}. {g}")
        
        grupi_valik = int(input("Sisesta nimekirja number: ")) - 1
        grupp = grupid[grupi_valik]
        
        # vali isik
        isikud = List_[grupp]
        print(f"\nVali isik nimekirjast '{grupp}':")
        for i, (kood, nimi) in enumerate(isikud.items(), 1):
            print(f"{i}. {nimi} ({kood})")
        
        isiku_valik = int(input("Sisesta isiku number: ")) - 1
        kood, nimi = list(isikud.items())[isiku_valik]
        
        print(f"\nSa valisid: {nimi} ({kood}) nimekirjast '{grupp}'")
        
        # võimalus muuta valikut
        kinnitus = input("Kinnita valik? (jah/ei): ").strip().lower()
        if kinnitus == "jah":
            return grupp, kood, nimi

    text = input("Sisesta sedeli tekst: ")
    return "Oma grupp", text, "Oma valik"
    
    return pick_choice(List_)

def load_pem(path: str) -> bytes:
    with open(path, "r", encoding="utf-8") as f:
        pem = f.read()
    lines = pem.strip().splitlines()
    b64 = "".join(l for l in lines if not l.startswith("-----"))
    return base64.b64decode(b64)

def generate_asice_file(asice_path, ballot_path, ivxv_collect = False):
    # digidoc-tool command
    cmd = [ ("/usr/local/bin/" if ivxv_collect else "") + "digidoc-tool" ]
    cmd.append("create")
    if ivxv_collect: cmd.append("--ivxvkey=ts.pem")
    cmd.append(f"--file={ballot_path}")
    cmd.append(asice_path)

    print(" ".join(a for a in cmd))

    env = os.environ.copy()
    if ivxv_collect: env["LD_LIBRARY_PATH"] = "/usr/local/lib"

    result = subprocess.run(cmd, env=env, capture_output=True)
    return result.stdout.decode(errors="ignore"), result.stderr.decode(errors="ignore")

def main():
    slots = get_slots_info()
    # Show available slots
    for i, slot in enumerate(slots, start=1):
        print(f"--- Slot {i} ---")
        for k, v in slot.items():
            if not k.startswith("_"):
                print(f"{k:20}: {v}")
        print()

    # Pick correct slot
    slot_pin1 = find_slot_by_label(slots, "PIN1")

    if slot_pin1 and "token label" in slot_pin1:
        token_label = slot_pin1["token label"]
        token_enc = urllib.parse.quote(token_label, safe='')  # URL encode
        pkcs11_key = f'pkcs11:type=private;token={token_enc};'
        print("PKCS11 openssl käsurea token")
        print(pkcs11_key)
    else:
        print("PIN1 tokenit ei leitud")
        return

    cert_file = export_cert_to_pem()  # ekspordib vaikimisi ./temp/cert.pem

    if not args.local:
        request_data = {
            "id": 0.0,
            "method": "RPC.VoterChoices",
            "params": [{"OS": "Röster 0.0.1", "AuthMethod": "tls"}]
        }

        #print("--- pem file ---")
        #print(cert_file)
        print("Alustame sessiooni ja küsime kandidaatide nimekirja")
        out, err = send_choices_request(request_data, token_label, cert_file)
        #print("--- STDOUT ---")
        #print(out)
        #print("--- STDERR ---")
        #print(err)
        choices=parse_choices_response(out)
        #print(json.dumps(choices, indent=4, ensure_ascii=False))
        
        with open("VoterChoices.json", "w", encoding="utf-8") as f:
            json.dump(choices, f, indent=4, ensure_ascii=False)

    ## read VoterChoice.json
    #with open("./VoterChoices.json", "r") as f:
    #    choices = json.load(f)

     ## custom ballot
    if ballot_file and args.ephemeral:
        print("--- Oma kryptogramm ---")
        with open(ballot_file, "rb") as f:
            crypt_bin = f.read()
        eph_key=int.from_bytes(base64.standard_b64decode(args.ephemeral), 'big')
    else:
        ## pick choice
        print("--- Vali valikutest ---")
        if args.message:
            message = args.message
        else:
            if args.local:
                message = input("Sisesta sedeli tekst: ")
            else:
                group, message, name = pick_choice(choices["result"]["List_"])

        ## make cryptogram
        bin_key = load_pem(args.key)
        curve = registry.get_curve("secp384r1")

        ## encode
        pk = PublicKey.from_public_bytes(bin_key)
        ct = pk.encode_and_encrypt(message, store_ephemeral=True)
        unblinded = ct.unblind(pk.H)
        crypt_bin = ct.to_bytes()
        eph_key = ct.ephemeral_random

    #read ephemeral
    num_bytes = (eph_key.bit_length() + 7) // 8  # vajalik baitide arv
    eph_key_bytes = eph_key.to_bytes(num_bytes, 'big')
    eph_key_str = base64.standard_b64encode(eph_key_bytes).decode('ascii')

    fn_root = f"./{args.round}.question-{args.question}"

    with open(fn_root+".ballot", "wb") as f:
        f.write(crypt_bin)
    with open(fn_root+".ballot.ephemeral", "w") as f:
        f.write(str(eph_key))

    ## generate asice file
    print("Allkirjasta valik PIN2 abil")
    asic_file = generate_asice_file(asice_path=fn_root+".asice", 
                                    ballot_path=fn_root+".ballot",
                                    ivxv_collect=args.collector)
    
    ## get asice file
    with open(fn_root+".asice", "rb") as f:
        asice_data = f.read()
    vote = base64.b64encode(asice_data).decode("utf-8")

    if not args.local:

        ## send vote
        request_data = {
            "id": choices["id"],
            "method": "RPC.Vote",
            "params": [
                {
                "OS": "Röster 0.0.1",
                "AuthMethod": "tls",
                "Choices": choices["result"]["Choices"],
                "Type": "bdoc",
                "SessionID": choices["result"]["SessionID"],
                "Vote": vote
                }
            ]
        }

        out, err = send_vote_tls_request(request_data, token_label, cert_file)
        #print("--- STDOUT ---")
        #print(out)
        #print("--- STDERR ---")
        #print(err)
        vote_data=parse_vote_response(out)

    with open(fn_root+".ballot", "rb") as f:
        ballot = f.read()

    #get time
    container = Container(io.BytesIO(asice_data))
    for xmlsig in container.iter_signatures():
        BallotMoment = xmlsig.get_signing_time()
        ocsp = xmlsig.get_ocsp_response().get_encapsulated_response()
        tsp = xmlsig.get_timestamp_response()

    if not args.local:
        if vote_data["error"] is not None:
            print("ERROR:", vote_data["error"])
            return        

        voteid = vote_data["result"]["VoteID"]
        sessid = choices["result"]["SessionID"]
        choics = choices["result"]["Choices"]

    else:

        voteid = base64.standard_b64encode(hashlib.md5(ballot).digest()).decode('ascii')
        sessid = base64.standard_b64encode(uuid.uuid4().bytes).decode('ascii')
        choices = None

    votesafe = voteid.replace("/","_")

    json_storage = {
        "BallotMoment": BallotMoment,
        "Ephemeral": eph_key_str,
        (fn_root+".ballot").lstrip("./"):  base64.standard_b64encode(ballot).decode('ascii'), 
        "VoteID": voteid,
        "error": None,
        "id": 1,
        "result": {
            "Choices": choices,
            "Qualification": {
                "ocsp": base64.standard_b64encode(ocsp).decode('ascii'),
                "tspreg": base64.standard_b64encode(tsp).decode('ascii')
            },
            "SessionID": sessid,
            "Type": "bdoc",
            "Vote": vote
        }
    }

    # write json
    print(f"{votesafe}.json")
    with open(f"{votesafe}.json", 'w') as outfile:
        json.dump(json_storage, outfile, sort_keys=True, indent=4)
    # write asice
    print(f"{votesafe}.asice")
    with open(f"{votesafe}.asice", "wb") as f:
        f.write(asice_data)

    # write qr
    print(f"{votesafe}.png")
    if not args.local:
        make_qr(sessid=vote_data["result"]["SessionID"], 
                ephkey=eph_key_str, 
                voteid=vote_data["result"]["VoteID"],
                filename=f"{votesafe}.png")
    else:
        make_qr(sessid=sessid, 
                ephkey=eph_key_str, 
                voteid=voteid,
                filename=f"{votesafe}.png")
        
    print("done")

if __name__ == "__main__":
    main()
