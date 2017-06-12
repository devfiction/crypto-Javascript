// g++ Driver.cpp -o D -lcryptopp

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;


#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/cast.h>
#include <cryptopp/serpent.h>
#include <cryptopp/twofish.h>
#include <cryptopp/seed.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <string>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using namespace CryptoPP;
using std::string;

#include <cstdlib>
using std::exit;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/serpent.h>
using CryptoPP::Serpent;

#include <cryptopp/modes.h>
using CryptoPP::CBC_Mode;

#include <cryptopp/secblock.h>

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using CryptoPP::SecByteBlock;

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	byte ivx[16];
	CBC_Mode<Serpent>::Decryption serpentEnc;
	std::string plainText;
	std::string cipherData;
	cipherData = "9ea101ecebaa41c712bcb0d9bab3e2e4";
	std::string key;
	key = "00000000000000000000000000000000";
	std::string iv;
	iv = "00000000000000000000000000000000";

	HexDecoder decoder;
	HexDecoder decoder2;
	HexDecoder decoder3;

        std::string decoded;
        decoder.Put((byte *)cipherData.data(), cipherData.size());
        decoder.MessageEnd();
        long size = decoder.MaxRetrievable();
        if (size) {
            decoded.resize(size);
            decoder.Get((byte *)decoded.data(), decoded.size());
        }
        cipherData = decoded;

	decoded = "";
        decoder2.Put((byte *)key.data(), key.size());
        decoder2.MessageEnd();
        size = decoder2.MaxRetrievable();
        if (size) {
            decoded.resize(size);
            decoder2.Get((byte *)decoded.data(), decoded.size());
        }
        key = decoded;

	SecByteBlock keyx((const unsigned char*)key.data(), key.length());

	decoded = "";
        decoder3.Put((byte *)iv.data(), iv.size());
        decoder3.MessageEnd();
        size = decoder3.MaxRetrievable();
        if (size) {
            decoded.resize(size);
            decoder3.Get((byte *)decoded.data(), decoded.size());
        }
        iv = decoded;
	memcpy(ivx, iv.data(), 16);

	serpentEnc.SetKeyWithIV(keyx, 32, ivx);
	StringSource ss(cipherData, true, new StreamTransformationFilter(serpentEnc, new StringSink(plainText), BlockPaddingSchemeDef::NO_PADDING));
        cipherData = plainText;



	std::string encoded;

        HexEncoder encoder;
        encoder.Put((byte *)cipherData.data(), cipherData.size());
        encoder.MessageEnd();

        size = encoder.MaxRetrievable();
        if (size) {
            encoded.resize(size);
            encoder.Get((byte *)encoded.data(), encoded.size());
        }
        cipherData = encoded;
	
	cout << "Result: " << cipherData.c_str() << "\r\n";

	return 0;
}

