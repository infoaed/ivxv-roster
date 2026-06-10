# ivxv-roster

Command line voting tool for Estonia's Internet Voting of 2015 onwards (IVXV)

```
usage: vote.py [-h] [--key KEY] [--message MESSAGE] [--ballot BALLOT] [--ephemeral EPHEMERAL] [--pin1 PIN1] [--pin2 PIN2] [--local] [--collector]
               [--round ROUND] [--question QUESTION]

options:
  -h, --help            show this help message and exit
  --key KEY, -k KEY     Hääletuse avaliku võtme fail
  --message MESSAGE, -m MESSAGE
                        Valiku kood, tüüpiliselt kujul 0000.000
  --ballot BALLOT, -b BALLOT
                        Balloti fail ehk sedel ise
  --ephemeral EPHEMERAL, -e EPHEMERAL
                        Efemeerse võtme väärtus base64 vormingus
  --pin1 PIN1           Isikutuvastuse PIN1 väärtus, puudumisel küsitakse
  --pin2 PIN2           Allkirjastamise PIN2 väärtus, puudumisel küsitakse(ei tööta)
  --local, -l           Täna serveriga juttu ei tee
  --collector, -c       Ajatemplile kogumisteenuse signatuur
  --round ROUND, -r ROUND
                        Valimiste identifikaator
  --question QUESTION, -q QUESTION
                        Küsimuse identifikaator
```

In order to use `--collector` option, [modified DigiDoc tool](https://github.com/infoaed/ivxv-libdigidocpp) is needed.
