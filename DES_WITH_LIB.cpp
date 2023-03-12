// Naudojama Cryptopp (Crypto++) biblioteka
#include <iostream>
#include <string>
#include <cstdlib>
#include <cryptlib.h>
#include <des.h>
#include <modes.h>
#include <filters.h>
#include <fstream>
#include <windows.h>

using namespace std;
using namespace CryptoPP;
// funkcija skirta konsoles teksto spalvom 
void SetColor(int ForgC) {
    WORD wColor;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hStdOut, &csbi))
    {
        wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
        SetConsoleTextAttribute(hStdOut, wColor);
    }
    return;
}

int main(int argc, char** argv)
{
    string tekstas, key, tekstoIsvedimas, sifruotoIsvedimas, isvestiFaila;
    int pasirinkimas, modas;

    // MENIU kuriame pasirenkame kaip norime ivesti teksta
    SetColor(13);
    cout << "\n                        DES SIFRAVIMO/DESIFRAVIMO ALGORITMAS" << endl;
    SetColor(14);
    cout << "\n_____________________________________________________________________________\n";
    cout << "\n<PASIRINKIMAS>\n";
    cout << "1. Ivesti teksta (plaintext) is konsoles.\n";
    cout << "2. Nuskaityti teksta (plaintext) is failo.\n";
    cout << "3. Nuskaityti uzsifruota teksta (plaintext) is output failo.\n";
    SetColor(9);
    cout << "Iveskite pasirinkima: ";
    SetColor(15);
    cin >> pasirinkimas;

    // Ivedamas tekstas (plaintext)
    // Konsoles teksto ivedimas
    if (pasirinkimas == 1) {
        SetColor(9);
        cout << "Iveskite teksta (plaintext): ";
        SetColor(15);
        cin.ignore();
        getline(cin, tekstas);
    }
    // Teksto ivedimas is pasirinkto failo
    else if (pasirinkimas == 2) {
        SetColor(9);
        cout << "Iveskite teksto failo varda: ";
        SetColor(15);
        string input_file_name;
        cin >> input_file_name;
        ifstream input_file(input_file_name);
        if (input_file.is_open()) {
            tekstas = string((istreambuf_iterator<char>(input_file)), istreambuf_iterator<char>());
            input_file.close();
        }
        else {
            SetColor(13);
            cout << "<KLAIDA> Nepavyko atidaryti teksto failo" << endl;
            SetColor(15);
            return 1;
        }
    }
    // Teksto ivedimas is output.txt failo
    else if (pasirinkimas == 3) {
        ifstream isvestiFaila("output.txt");
        tekstas = string((istreambuf_iterator<char>(isvestiFaila)), istreambuf_iterator<char>());
    }
    else {
        SetColor(13);
        cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
        SetColor(15);
        return 1;
    }

    // Rakto ivedimas
    SetColor(9);
    cout << "Iveskite rakta (KEY): ";
    SetColor(15);
    cin>> key;

    // MENIU kuriame pasirenkame ar uzsifruoti ar desifruoti
    SetColor(14);
    cout << "\n_____________________________________________________________________________\n";
    cout << "\n<PASIRINKIMAS>\n";
    cout << "1. Uzsifruoti teksta (plaintext).\n";
    cout << "2. Desifruoti teksta (plaintext).\n";
    SetColor(9);
    cout << "Iveskite pasirinkima: ";
    SetColor(15);
    cin >> pasirinkimas;

    // MENIU kuriame pasirenkame viena is modu, kuriuo atliksime sifravima/desifravima
    SetColor(14);
    cout << "\n_____________________________________________________________________________\n";
    cout << "\n<PASIRINKIMAS>\n";
    cout << "1. ECB modas" << endl;
    cout << "2. CBC modas" << endl;
    cout << "3. CFB modas" << endl;
    cout << "4. OFB modas" << endl;
    cout << "5. CTR modas" << endl;
    SetColor(9);
    cout << "Iveskite pasirinkima: ";
    SetColor(15);
    cin >> modas;

    try
    {
        // Nustatom DES sifravima/desifravima pagal skirtingus modus
        CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption encrypt_ecb;
        CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption decrypt_ecb;
        CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption encrypt_cbc;
        CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption decrypt_cbc;
        CryptoPP::CFB_Mode<CryptoPP::DES>::Encryption encrypt_cfb;
        CryptoPP::CFB_Mode<CryptoPP::DES>::Decryption decrypt_cfb;
        CryptoPP::OFB_Mode<CryptoPP::DES>::Encryption encrypt_ofb;
        CryptoPP::OFB_Mode<CryptoPP::DES>::Decryption decrypt_ofb;
        CryptoPP::CTR_Mode<CryptoPP::DES>::Encryption encrypt_ctr;
        CryptoPP::CTR_Mode<CryptoPP::DES>::Decryption decrypt_ctr;

        if (modas == 1)// ECB
        {
            if (pasirinkimas == 1)
            {
                encrypt_ecb.SetKey((byte*)key.c_str(), key.length());
                StringSource(tekstas, true, new StreamTransformationFilter(encrypt_ecb, new StringSink(sifruotoIsvedimas)));
                tekstoIsvedimas = tekstas;
            }
            else if (pasirinkimas == 2)
            {
                decrypt_ecb.SetKey((byte*)key.c_str(), key.length());
                StringSource(tekstas, true, new StreamTransformationFilter(decrypt_ecb, new StringSink(tekstoIsvedimas)));
                sifruotoIsvedimas = tekstas;
            }
            else
            {
                SetColor(13);
                cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
                SetColor(15);
                return 1;
            }
        }
        else if (modas == 2)// CBC
        {
            byte iv[CryptoPP::DES::BLOCKSIZE];
            memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

            if (pasirinkimas == 1)
            {
                encrypt_cbc.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(encrypt_cbc, new StringSink(sifruotoIsvedimas)));
                tekstoIsvedimas = tekstas;
            }
            else if (pasirinkimas == 2)
            {
                decrypt_cbc.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(decrypt_cbc, new StringSink(tekstoIsvedimas)));
                sifruotoIsvedimas = tekstas;
            }
            else
            {
                SetColor(13);
                cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
                SetColor(15);
                return 1;
            }
        }
        else if (modas == 3)// CFB
        {
            byte iv[CryptoPP::DES::BLOCKSIZE];
            memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

            if (pasirinkimas == 1)
            {
                encrypt_cfb.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(encrypt_cfb, new StringSink(sifruotoIsvedimas)));
                tekstoIsvedimas = tekstas;
            }
            else if (pasirinkimas == 2)
            {
                decrypt_cfb.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(decrypt_cfb, new StringSink(tekstoIsvedimas)));
                sifruotoIsvedimas = tekstas;
            }
            else
            {
                SetColor(13);
                cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
                SetColor(15);
                return 1;
            }
        }

        else if (modas == 4)// OFB
        {
            byte iv[CryptoPP::DES::BLOCKSIZE];
            memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

            if (pasirinkimas == 1)
            {
                encrypt_ofb.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(encrypt_ofb, new StringSink(sifruotoIsvedimas)));
                tekstoIsvedimas = tekstas;
            }
            else if (pasirinkimas == 2)
            {
                decrypt_ofb.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(decrypt_ofb, new StringSink(tekstoIsvedimas)));
                sifruotoIsvedimas = tekstas;
            }
            else
            {
                SetColor(13);
                cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
                SetColor(15);
                return 1;
            }
        }
        else if (modas == 5)// CTR
        {
            byte iv[CryptoPP::DES::BLOCKSIZE];
            memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

            if (pasirinkimas == 1)
            {
                encrypt_ctr.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(encrypt_ctr, new StringSink(sifruotoIsvedimas)));
                tekstoIsvedimas = tekstas;
            }
            else if (pasirinkimas == 2)
            {
                decrypt_ctr.SetKeyWithIV((byte*)key.c_str(), key.length(), iv);
                StringSource(tekstas, true, new StreamTransformationFilter(decrypt_ctr, new StringSink(tekstoIsvedimas)));
                sifruotoIsvedimas = tekstas;
            }
            else
            {
                SetColor(13);
                cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
                SetColor(15);
                return 1;
            }
        }
        else
        {
            SetColor(13);
            cout << "<KLAIDA> neteisingai ivestas pasirinkimas" << endl;
            SetColor(15);
            return 1;
        }
        // Gautu rezultatu isvedimas
        SetColor(14);
        cout << "\n_____________________________________________________________________________\n";
        cout << "\nUzsifruotas tekstas (ciphertext): ";
        SetColor(34);
        cout << sifruotoIsvedimas << endl;
        // Uzsifruoto teksto issaugojimas output.txt faile
        ofstream isvestiFaila("output.txt");
        isvestiFaila << sifruotoIsvedimas;
        SetColor(14);
        cout << "Neuzsifruotas tekstas (plaintext): ";
        SetColor(34);
        cout << tekstoIsvedimas;
        SetColor(15);
    }
    // tikrinam ar yra klaida
    catch (const CryptoPP::Exception& e)
    {
        cerr << "KLAIDA: " << e.what() << endl;
        return 1;
    }
    SetColor(8);
    return 0;
}
