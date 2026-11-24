# Kas tai?

Nuo ~2026 Balandžio [OpenSC](https://github.com/OpenSC/OpenSC) projektas turi
`lteid` tvarkyklę palaikančia Lietuvišką asmens tapatybės kortelę. Tačiau,
vien tvarkyklės patogiam darbui neužtenka. Todėl egzistuoja šis `lt-eid`
paketas kuris:

- Pasirūpina visa reikalinga konfigūracija
- Leidžia grafinėje aplinkoje įvesti CAN ("card access number") kodą
- Imituoja papildomą programinę įrangą reikalingą prisijungti prie [epaslaugos.lt](https://epaslaugos.lt/)
- Valdo priėjimą prie kortelės informacijos ir leidžia kortele naudotis
kelioms programoms vienu metu

Su šiuo paketu, USB lustinių kortelių skaitytuvu ir ATK galima:

- Prisijungti prie valstybinių institucijų interneto svetainių per https://ipasas.lt/
- Prisijungti prie valstybinių institucijų interneto svetainių per https://epaslaugos.lt/
- Pasirašyti PDF dokumentus kvalifikuotu elektroniniu parašu su [Autogram](https://docs.autogram.slovensko.digital/en/)
  ([instrukcijos](https://github.com/tadas-s/lt-eid/wiki/PDF-para%C5%A1ai-su-Autogram))

# Kodėl?

- Oficiali VRM pateikiama programa [mCard Toolbox veikia prastai, atnaujinama retai](https://tadas-s.github.io/doc/lithuanian_electronic_identity_card/)
- epaslaugos.lt reikalinga papildoma programinė įranga Elpako Signer Linux
aplinkai padaryta atmestinai, veikia prastai

# Vartotojo gidas / informacija

https://github.com/tadas-s/lt-eid/wiki

# Klausimai / pagalba

Pradėkite temą [diskusijų skiltyje](https://github.com/tadas-s/lt-eid/discussions), arba, 
jei neturite/nenorite GitHub paskyros - rašykite [tadas@yoyo.lt](mailto:tadas@yoyo.lt).

# Atsakomybės apribojimas

Tai savanoriškas, laisvalaikiu kuriamas projektas. Programinė įranga
teikiama "tokia, kokia yra", be jokių garantijų: nei dėl jos veikimo, nei
dėl tinkamumo kokiam nors tikslui, nei dėl saugumo. Ja naudojatės savo pačių
rizika. Projektas nėra susijęs su jokiomis valstybės institucijomis (pvz.,
VRM ar Asmens dokumentų išrašymo centru) ar epaslaugos.lt kūrėjais ir nėra
jų patvirtintas ar remiamas. Išsamiau – [LGPL-2.1 licencijoje](LICENSE).
