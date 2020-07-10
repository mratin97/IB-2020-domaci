# IB-2020-domaci
IB-2020 domaci


Napravio sam odbojene foldere za domaci i projekat,Projekat je malo bloatovan jer mi je pocetna tacka bila domaci, neke nepotrebne stvari su zakomentarisane dok neke bezveze stoje u kodu



Pokretanjem writeMailClienta pokrece se aplikacija za slanje emaila.Uneti inputi body i subject se uzimaju od njih se pravi xml fajl sa elementima body i subject(posle svakog stepa sam snjimao sadrzaj u novi xml fajl radi bolje preglednosti resenja ovaj xml fajl se zove emailsigned.xml),zatim se uzima dati dokument i potpisuje(emailsigned1.xml),nakon toga enkriptujemo xml fajl(emailPotpisanIEnkriptovan.xml),pretvaramo taj xml u string i saljemo ga kroz body emaila.

Pokretanjem mailReaderClienta pokrece se aplikacija za citanje emaila.Uzimamo sadrzaj body-a pomocu mailhelper classe konvertujemo sadrzaj u xml(emailPotpisanIEnkriptovan2.xml),dekriptujemo dokument(emailDekriptovan.xml),i na kraju proveravamo potpis(Ovaj deo mi iz nekog razloga ne radi,pokusao sam i emailsigned1.xml da provucem kroz funkciju za validaciju potpisa ali idalje mi je bacalo false).U konzoli se ispisuje dekriptovan subject i body kao i cela xml poruka.
