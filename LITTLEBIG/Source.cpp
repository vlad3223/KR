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


// Переменные

typedef struct
{
	octet s[32];		/*< переменная s */
	octet r[32];		/*< переменная r */
	octet block[32];	/*< блок выходных данных */
	size_t reserved;	/*< резерв выходных октетов */
	octet state_ex[];	/*< [2 beltHash_keep()] хэш-состояния */
} brng_ctr_st;
bign_params params[1];
err_t errorCode = 0;
octet privkey[64];
octet pubkey[128];
octet brng_state[1024];
octet theta[32];
octet pwd[8]; ;
octet state[1024];
octet buf[64];
octet recBuf[192];
octet _hash[96];
octet sig[96];
octet oid_der[128];
size_t oid_len = 0;



int usage();
void generateKey();
void encryptKey();
void printKey(char*, char*);
void printKeyOnConsole();
void sign();
void check_sign();
void correct_exit();

static void brngBlockNeg(octet dest[32], const octet src[32]);

static void brngBlockXor2(octet dest[32], const octet src[32]);

static void brngBlockInc(octet block[32]);

size_t brngCTR_keep();
void brngCTRStart(void* state, const octet key[32], const octet iv[32]);
void brngCTRStepR(void* buf, size_t count, void* state);




int main(int argc, char* argv[]) {

	// Нет входных параметров
	if (argc < 2)
		return usage();

	// Вывод справки
	if (strCmp(argv[1], "-h") == 0 && 
		argc == 2)
		return usage();

	// Выработка открытого и личного ключей, шифрование и вывод в файл
	if (strCmp(argv[1], "-p") == 0  && 
		strCmp(argv[3], "-pub") == 0 &&
		strCmp(argv[5], "-priv") == 0 &&
		argc == 7) {
		memCopy(pwd, argv[2], strLen(argv[2]));
		generateKey();
		printKeyOnConsole();
		encryptKey();
		printKey(argv[4], argv[6]);
		correct_exit();
		return 0;
	}

	// Подпись файла
	if (strCmp(argv[1], "-s") == 0 && 
		argc == 3)
	{
		printf("Generating digital signature...\n");
		FILE* fp = fopen(argv[2], "r+b");
		fread(_hash, sizeof(octet), 96, fp);
		generateKey();
		sign();
		hexFrom((char*)recBuf, sig, 96);
		fwrite(recBuf, sizeof(octet), 192, fp);
		fclose(fp);
		correct_exit();
		return 0;
	}

	// Проверка ЭЦП
	if (strCmp(argv[1], "-c") == 0 && 
		argc == 3) {
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
		correct_exit();
		return 0;
	}

	
	return usage();
}

void correct_exit() {
	memSet(privkey, (octet)"0", 64);
	memSet(theta, (octet)"0", 32);
}

void generateKey() {
	// Загрузка стандартных параметров	
	// Updated elliptical curve
	errorCode = bignStdParams(params, "1.2.112.0.2.0.34.101.45.3.1"); // Таблица Б1 из СТБ 34.101.45
	if (!errorCode == ERR_OK)
		printf("Error assuming loading paramethers: %d\n", errorCode);


	// Установка ГПСЧ
	brngCTRStart(state, beltH() + 128, beltH() + 128 + 64);


	// Генерация ключей
	bignGenKeypair(privkey, pubkey, params, brngCTRStepR, brng_state);


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
		if (pubkey[i] <= 0x0f)
			printf("0%x", pubkey[i]);
		else
			printf("%x", pubkey[i]);
	}
	printf("\n");
}

void sign() {
	oid_len = sizeof(oid_der);
	bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
	if(bignSign(sig, params, oid_der, oid_len, _hash, privkey, brngCTRStepR, brng_state)==ERR_OK)
		printf("generated successful!\n");

	
}

void printKey(char* pub, char* priv) {
	// Запись зашфрованного ключа в файл
	FILE* fp = fopen(priv, "w+b");
	FILE* fz = fopen(pub, "w+b");
	fwrite(buf, sizeof(octet), strlen((char*)buf), fp);
	fwrite(pubkey, sizeof(octet), 128, fz);
	fclose(fp);
	fclose(fz);
	printf("\nPrivate key: \n"
		   "was been encrypted and written to the file %s\n\n", priv);
	printf("\nPublic key: \n"
		"was been written to the file %s\n\n", pub);
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
		"------------------------------------------------------------------------------------------------------------------------\n"
		"This simple utility allow you generate public/private key and \n"
		"check/generate digital signature of the choosen file.\n"
		"Usage:\n"
		"	LITTLEBIG  -p password -pub pubkey_file -priv privatekey_file       generate private and public key\n"
		"	LITTLEBIG  -s <file_to_create_signature>                            generate digital signature and signing file\n"
		"	LITTLEBIG  -c <file_to_check_signature>                             validating digital signature of file\n"
		"	LITTLEBIG  -h                                                       help\n"
		"------------------------------------------------------------------------------------------------------------------------\n"
	);
	return 0;
}

void check_sign() {
	oid_len = sizeof(oid_der);
	bignOidToDER(oid_der, &oid_len, "1.2.112.0.2.0.34.101.31.81");
	if (bignVerify(params, oid_der, oid_len, _hash, sig, pubkey) != ERR_OK)
		printf("Sign is'n valid!\n");
	else
		printf("Sign is valid!\n");
}

static void brngBlockNeg(octet dest[32], const octet src[32])
{
	register size_t i = W_OF_O(32);
	while (i--)
		((word*)dest)[i] = ~((const word*)src)[i];
}

static void brngBlockXor2(octet dest[32], const octet src[32])
{
	register size_t i = W_OF_O(32);
	while (i--)
		((word*)dest)[i] ^= ((const word*)src)[i];
}

static void brngBlockInc(octet block[32])
{
	register size_t i = 0;
	word* w = (word*)block;
	do
	{
#if (OCTET_ORDER == BIG_ENDIAN)
		w[i] = wordRev(w[i]);
		++w[i];
		w[i] = wordRev(w[i]);
#else
		++w[i];
#endif
	} while (w[i] == 0 && i++ < W_OF_O(32));
	i = 0;
}

size_t brngCTR_keep()
{
	return sizeof(brng_ctr_st) + 2 * beltHash_keep();
}
void brngCTRStart(void* state, const octet key[32], const octet iv[32])
{
	brng_ctr_st* s = (brng_ctr_st*)state;
	ASSERT(memIsDisjoint2(s, brngCTR_keep(), key, 32));
	ASSERT(iv == 0 || memIsDisjoint2(s, brngCTR_keep(), iv, 32));
	// обработать key
	beltHashStart(s->state_ex + beltHash_keep());
	beltHashStepH(key, 32, s->state_ex + beltHash_keep());
	//	сохранить iv
	if (iv)
		memCopy(s->s, iv, 32);
	else
		memSetZero(s->s, 32);
	//	r <- ~s
	brngBlockNeg(s->r, s->s);
	// нет выходных данных
	s->reserved = 0;
}
void brngCTRStepR(void* buf, size_t count, void* state)
{
	brng_ctr_st* s = (brng_ctr_st*)state;
	ASSERT(memIsDisjoint2(buf, count, s, brngCTR_keep()));
	// есть резерв данных?
	if (s->reserved)
	{
		if (s->reserved >= count)
		{
			memCopy(buf, s->block + 32 - s->reserved, count);
			s->reserved -= count;
			return;
		}
		memCopy(buf, s->block + 32 - s->reserved, s->reserved);
		count -= s->reserved;
		buf = (octet*)buf + s->reserved;
		s->reserved = 0;
	}
	// цикл по полным блокам
	while (count >= 32)
	{
		// Y_t <- belt-hash(key || s || X_t || r)
		memCopy(s->state_ex, s->state_ex + beltHash_keep(), beltHash_keep());
		beltHashStepH(s->s, 32, s->state_ex);
		beltHashStepH(buf, 32, s->state_ex);
		beltHashStepH(s->r, 32, s->state_ex);
		beltHashStepG((octet*)buf, s->state_ex);
		// next
		brngBlockInc(s->s);
		brngBlockXor2(s->r, (octet*)buf);
		buf = (octet*)buf + 32;
		count -= 32;
	}
	// неполный блок?
	if (count)
	{
		// block <- beltHash(key || s || zero_pad(X_t) || r)
		memSetZero(s->block + count, 32 - count);
		memCopy(s->state_ex, s->state_ex + beltHash_keep(), beltHash_keep());
		beltHashStepH(s->s, 32, s->state_ex);
		beltHashStepH(buf, count, s->state_ex);
		beltHashStepH(s->block + count, 32 - count, s->state_ex);
		beltHashStepH(s->r, 32, s->state_ex);
		beltHashStepG(s->block, s->state_ex);
		// Y_t <- left(block)
		memCopy(buf, s->block, count);
		// next
		brngBlockInc(s->s);
		brngBlockXor2(s->r, s->block);
		s->reserved = 32 - count;
	}
}
