#pragma comment(lib, "bee2.lib")
#pragma comment(lib, "libbee2.lib")
#define _CRT_SECURE_NO_WARNINGS



#include "bee2/core/hex.h"
#include "bee2/core/str.h"
#include "bee2/crypto/belt.h"
#include "bee2/core/mem.h"
#include "bee2/crypto/bign.h"
#include "bee2/core/util.h"
#include "bee2/crypto/brng.h"
#include <iostream>
#include <fstream>
#include <stdio.h>

using namespace std;

static size_t brngCTRX_keep();
static void brngCTRXStart(const octet theta[32], const octet iv[32], const void* X, size_t count, void* state);
static void brngCTRXStepR(void* buf, size_t count, void* stack);

int usage();
void generateKey();
void encryptKey();
void printKey();
void printKeyOnConsole();
void sign();
void check_sign();


// Переменные
typedef struct
{
	const octet* X;		/*< дополнительное слово */
	size_t count;		/*< размер X в октетах */
	size_t offset;		/*< текущее смещение в X */
	octet state_ex[];	/*< состояние brngCTR */
} brng_ctrx_st;
bign_params params[1] ;
err_t errorCode=0;
octet privkey[64];
octet pubkey[128];
octet brng_state[1024];
octet theta[32];
octet pwd[8];  // "B194BAC80A08F53B";
octet state[1024];
octet buf[64];
octet recBuf[192];
octet _hash[96];
octet sig[96];
octet oid_der[128];
size_t oid_len = 0;


int main(int argc, char* argv[]) {

	// Нет входных параметров
	if (argc < 2)
		return usage();

	// Вывод справки
	if (strCmp(argv[1], "-h") == 0 && argc == 2)
		return usage();

	// Выработка открытого и личного ключей, шифрование и вывод в файл
	if (strCmp(argv[1], "-p") == 0 && argc == 3) {
		memCopy(pwd, argv[2], strLen(argv[2]));
		generateKey();
		printKeyOnConsole();
		encryptKey();
		printKey();
		return 0;
	}

	// Подпись файла
	if (strCmp(argv[1], "-s") == 0 && argc == 3)
	{
		printf("Generating digital signature...\n");
		FILE* fp = fopen(argv[2], "r+b");
		fread(_hash, sizeof(octet), 96, fp);
		generateKey();
		sign();
		hexFrom((char*)recBuf, sig, 96);
		fwrite(recBuf, sizeof(octet), 192, fp);
		fclose(fp);
		return 0;
	}

	// Проверка ЭЦП
	if (strCmp(argv[1], "-c") == 0 && argc == 3) {
		printf("Validating digital signature...\n");
		FILE* fp = fopen(argv[2], "r+b");
		fseek(fp, 0, SEEK_END);
		int lSize = ftell(fp);
		rewind(fp);
		fread(_hash, sizeof(octet), lSize-192, fp);
		fseek(fp, -192, SEEK_END);
		fread(recBuf, sizeof(octet), 192, fp);
		hexTo(sig, (char*)recBuf);
		generateKey();
		check_sign();
		fclose(fp);
		return 0;
	}

	
	return usage();
}


void generateKey() {
	// Загрузка стандартных параметров	
	errorCode = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.3"); // Таблица Б1 из СТБ 34.101.45
	if (!errorCode == ERR_OK)
		printf("Error assuming loading paramethers: %d\n", errorCode);


	// Установка ГПСЧ
	brngCTRXStart(beltH() + 128, beltH() + 128 + 64, beltH(), 8 * 32, brng_state);


	// Генерация ключей
	bignGenKeypair(privkey, pubkey, params, brngCTRXStepR, brng_state);


	// Проверка сгенерированного личного ключа
	if (!hexEq(privkey, "1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269"))
		printf("Error assuming generated private key!\n");


	// Проверка сгенерированного открытого ключа
	errorCode = bignValPubkey(params, pubkey);
	if (errorCode != ERR_OK)
		printf("Error assuming generated public key: %d\n", errorCode);
};

void printKeyOnConsole() {
	// Вывод на экран открытого ключа
	printf("\nPublic key: \n");
	for (int i = 0; i < 64; i++) {
		if (i == 32)
			printf("\n");
		if (i % 2 == 0 && (i != 0 && i != 32))
			printf(":");
		if (pubkey[i] < 0x0f)
			printf("0%x", pubkey[i]);
		else
			printf("%x", pubkey[i]);
	}
	printf("\n");
}

void sign() {
	oid_len = sizeof(oid_der);
	bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
	if(bignSign(sig, params, oid_der, oid_len, _hash, privkey, brngCTRXStepR, brng_state)==ERR_OK)
		printf("generated successful!\n");
	
}

void printKey() {
	// Запись зашфрованного ключа в файл
	FILE* fp = fopen("private_key.txt", "w+b");
	fwrite(buf, sizeof(octet), strlen((char*)buf), fp);
	fclose(fp);
	printf("\nPrivate key: \n"
		   "was been encrypted and written to the file private_key.txt\n\n");
}

void encryptKey() {
	// Построение ключа шифрования theta (beltKWP) файла по паролю pwd
	beltPBKDF2(theta, (const octet*)pwd, strLen((const char*)pwd), 10000, beltH() + 128 + 64, 8);

	// Начало процедуры зашифрования ключа
	ASSERT(sizeof(state) >= beltKWP_keep());
	beltKWPStart(state, theta, 32);
	memCopy(buf, privkey, strLen((char*)privkey));
	beltKWPStepE(buf, 64, state); // шифруем
}

int usage() {
	printf(
		"------------------------------------------------------------------------------------------------------\n"
		"This simple utility allow you generate public/private key and \n"
		"check/generate digital signature of the choosen file.\n"
		"Usage:\n"
		"	LITTLEBIG  -p password                          generate private and public key\n"
		"	LITTLEBIG  -s <file_to_create_signature>        generate digital signature and signing file\n"
		"	LITTLEBIG  -c <file_to_check_signature>         validating digital signature of file\n"
		"	LITTLEBIG  -h                                   help\n"
		"------------------------------------------------------------------------------------------------------\n"
	);
	return 0;
}

void check_sign() {
	oid_len = sizeof(oid_der);
	bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
	if (bignVerify(params, oid_der, oid_len, _hash, sig, pubkey) != ERR_OK)
		printf("Sign is not valid!\n");
	else
		printf("Sign is valid!\n");
}

static size_t brngCTRX_keep()
{
	return sizeof(brng_ctrx_st) + brngCTR_keep();
}

static void brngCTRXStart(const octet theta[32], const octet iv[32], const void* X, size_t count, void* state)
{
	brng_ctrx_st* s = (brng_ctrx_st*)state;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	ASSERT(count > 0);
	ASSERT(memIsValid(s->state_ex, brngCTR_keep()));
	brngCTRStart(s->state_ex, theta, iv);
	s->X = (const octet*)X;
	s->count = count;
	s->offset = 0;
}

static void brngCTRXStepR(void* buf, size_t count, void* stack)
{
	brng_ctrx_st* s = (brng_ctrx_st*)stack;
	octet* buf1 = (octet*)buf;
	size_t count1 = count;
	ASSERT(memIsValid(s, sizeof(brng_ctrx_st)));
	// заполнить buf
	while (count1)
		if (count1 < s->count - s->offset)
		{
			memCopy(buf1, s->X + s->offset, count1);
			s->offset += count1;
			count1 = 0;
		}
		else
		{
			memCopy(buf1, s->X + s->offset, s->count - s->offset);
			buf1 += s->count - s->offset;
			count1 -= s->count - s->offset;
			s->offset = 0;
		}
	// сгенерировать
	brngCTRStepR(buf, count, s->state_ex);
}