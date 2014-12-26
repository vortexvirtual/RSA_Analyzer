/* Vortex Virtual - RSA Analyzer.
 * http://www.vortexvirtual.com.br/
 *
 * Glaudson Ocampos <glaudson@securitylabs.com.br>
 * Nash Leon - <nashleon2.0@gmail.com>
 *
 * Compile com:
 *
 * $ gcc -o rsa_analyzer rsa_analyzer.c -lssl -lcrypto -Wall
 *
 * Atualizado em Novembro de 2014.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define 	ERRO		-1
#define		VERSAO		"v1.0"
#define		BANNER1		"Vortex Virtual"
#define		BANNER2		"RSA Analyzer"

#define		SITE		"http://www.vortexvirtual.com.br"
#define		AUTOR		"Glaudson Ocampos"
#define		EMAIL		"glaudson@securitylabs.com.br"

#define	NUMERO_BITS_MASTERKEY	64 		//SSL define valor de MASTER-KEY.
#define MAXTRY					65537	//Valor considerado seguro, atualmente(2014).
void exibe_banner() {
	fprintf(stdout, "%s\n%s\n%s - Versao %s\n\n", BANNER1, SITE, BANNER2,
			VERSAO);
	fflush(stdout);
}

/* Exibimos qual o valor aceitavel para o expoente
 * e para um determinado modulo N de X bits.
 */
void display_valor_aceitavel_e(char *valor) {
	BIGNUM *MK = NULL, *r = NULL, *p = NULL;
	char numero[4096];
	unsigned int nbits = NUMERO_BITS_MASTERKEY;
	unsigned int i = 0;
	BN_CTX *ctx;

	exibe_banner();

	int val = atoi(valor);
	if (val < 0) {
		fprintf(stderr, "Argumento possui valor negativo!\n");
		exit(ERRO);
	}

	memset(numero, 0x0, sizeof(numero));

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "Erro na criacao de BN_CTX\n");
		fflush(stderr);
		exit(ERRO);
	}

	r = BN_CTX_get(ctx);
	if (r == NULL) {
		fprintf(stderr, "Erro na criacao do BIGNUM de Resposta (r)!\n");
		fflush(stderr);
		exit(ERRO);
	}

	p = BN_CTX_get(ctx);
	if (p == NULL) {
		fprintf(stderr, "Erro na criacao do BIGNUM de Potencia (p)!\n");
		fflush(stderr);
		exit(ERRO);
	}

	MK = BN_CTX_get(ctx);
	if (MK == NULL) {
		fprintf(stderr, "Erro na criacao de Bignum para Master-Key!\n");
		fflush(stderr);
		exit(ERRO);
	}

	fprintf(stdout, "Gerando Pseudo Master-Key DES = 64 bits..\n");
	fflush(stdout);
	srand(100);

	/* Geramos um primos qualquer para ser Master-Key */
	if ((BN_generate_prime(MK, nbits, 1, NULL, NULL, NULL, NULL)) == NULL) {
		fprintf(stderr, "Erro na geracao do numero primo!\n");
		BN_free(MK);
		BN_free(r);
		BN_free(p);
		exit(ERRO);
	}

	fprintf(stdout, "OK.\nPseudo Master-Key (%s)", BN_bn2hex(MK));
	fflush(stdout);

	for (i = 2; i < MAXTRY; i++) {
		sprintf(numero, "%d", i);
		BN_dec2bn(&p, numero);

		fprintf(stdout, "Elevando Pseudo Mensagem - Master-Key (%s) a %s = ",
				BN_bn2hex(MK), BN_bn2dec(p));
		fflush(stdout);
		if (BN_exp(r, MK, p, ctx) == 0) {
			fprintf(stderr, "Erro na elevacao a potencia!\n");
			BN_free(MK);
			BN_free(r);
			BN_free(p);
			exit(ERRO);
		}

		fprintf(stdout, "%s\n", BN_bn2hex(r));
		fflush(stdout);

		if (BN_num_bits(r) > val) {
			fprintf(stdout, "\n**** Valor Minimo aceitavel para e: %s ****\n",
					BN_bn2dec(p));
			fprintf(stdout,
					"\n**** Tamanho em Bits de Master-Key elevado a e: %d ****\n",
					BN_num_bits(r));
			fflush(stdout);
			break;
		}
	}

	BN_free(MK);
	BN_free(r);
	BN_free(p);
}

/* Checamos e exibimos o tamanho em bits de um bignum */

void checa_tamanho_bignum(char *numero) {
	BIGNUM *N = NULL;
	unsigned int nbits = 0;

	exibe_banner();

	N = BN_new();
	if (N == NULL) {
		fprintf(stderr, "Erro na criacao de Bignum!\n");
		fflush(stderr);
		exit(ERRO);
	}

	BN_hex2bn(&N, numero);

	nbits = BN_num_bits(N);
	fprintf(stdout, "*** Numero de Bits: %d ***\n", nbits);
	fflush(stdout);
	BN_free(N);
}

/* Checamos se um determinado numero eh primo */
void checa_primo_bignum(char *numero) {
	BIGNUM *N = NULL;
	int r = 0;

	exibe_banner();

	N = BN_new();
	if (N == NULL) {
		fprintf(stderr, "Erro na criacao de Bignum!\n");
		fflush(stderr);
		exit(ERRO);
	}

	BN_hex2bn(&N, numero);

	/* OpenSSL executa o teste de Miller-Rabin para saber
	 * se o numero eh primo.
	 */
	r = BN_is_prime(N, 10, NULL, NULL, NULL);
	if (r == 0) {
		fprintf(stdout, "\n*** Numero Composto! ***\n");
		fflush(stdout);
	} else if (r == 1) {
		fprintf(stdout, "\n*** Numero Primo! ***\n");
		fflush(stdout);
	} else {
		fprintf(stderr, "\nProblemas na checagem do numero!\n");
		fflush(stderr);
	}

	BN_free(N);
}

/* Exibimos informacoes de um certificado.
 */
void display_info_certificado(char *certificado) {
	BIO *certbio = NULL;
	BIO *outbio = NULL;
	X509 *cert = NULL;
	int ret = 0;
	X509_CINF *ci = NULL;
	EVP_PKEY *pkey = NULL;

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	certbio = BIO_new(BIO_s_file());
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	ret = BIO_read_filename(certbio, certificado);
	if (ret == 0) {
		fprintf(stderr, "Erro na leitura do arquivo de certificado!\n");
		fflush(stderr);
		_exit(ERRO);
	}

	if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
		BIO_printf(outbio, "Falha no carregamento do certificado!\n");
		exit(-1);
	}

	BIO_printf(outbio, "Emissor: ");
	X509_NAME_print(outbio, X509_get_issuer_name(cert), 0);
	BIO_printf(outbio, "\n");

	BIO_printf(outbio, "Valido de: ");
	ASN1_TIME_print(outbio, X509_get_notBefore(cert));
	BIO_printf(outbio, "\n");

	BIO_printf(outbio, "Valido ate: ");
	ASN1_TIME_print(outbio, X509_get_notAfter(cert));
	BIO_printf(outbio, "\n");

	BIO_printf(outbio, "Subject: ");
	X509_NAME_print(outbio, X509_get_subject_name(cert), 0);
	BIO_printf(outbio, "\n");

	pkey = X509_get_pubkey(cert);
	EVP_PKEY_print_public(outbio, pkey, 0, NULL);
	EVP_PKEY_free(pkey);

	ci = cert->cert_info;
	X509V3_extensions_print(outbio, "Extensoes X509v3", ci->extensions,
			X509_FLAG_COMPAT, 0);

	X509_signature_print(outbio, cert->sig_alg, cert->signature);

	X509_free(cert);
	BIO_free_all(certbio);
	BIO_free_all(outbio);
	exit(0);
}

void uso(char *progname) {
	fprintf(stdout, "%s\n%s\n%s - Versao %s\n", BANNER1, SITE, BANNER2, VERSAO);
	fprintf(stdout, "Desenvolvido por %s <%s>\n\n", AUTOR, EMAIL);
	fprintf(stdout, "%s [opcoes]\n\n", progname);
	fprintf(stdout,
			"-n <bignum>\t\t\tCheca tamanho de BIGNUM (em hexadecimal)\n");
	fprintf(stdout,
			"-p <bignum>\t\t\tCheca se BIGNUM (em hexadecimal) eh primo\n");
	fprintf(stdout,
			"-x <certificado>\t\tExtrai Informacoes de um Certificado\n");
	fprintf(stdout,
			"-a <tamanho_modulo_N>\t\tExibe valor aceitavel para expoente publico (e) em relacao ao modulo N (mod N)\n");
	fprintf(stdout, "-h \t\t\t\tExibe essa tela de ajuda.\n\n\n");
}

int main(int argc, char *argv[]) {
	int c;
	char *valor;

	if (argc < 2) {
		uso(argv[0]);
	}

	while ((c = getopt(argc, argv, "a:n:p:x:h?")) != -1) {
		switch (c) {
		case 'a':
			valor = optarg;
			display_valor_aceitavel_e(valor);
			break;
		case 'n':
			valor = optarg;
			checa_tamanho_bignum(valor);
			break;
		case 'x':
			valor = optarg;
			display_info_certificado(valor);
			break;
		case 'p':
			valor = optarg;
			checa_primo_bignum(valor);
			break;
		case '?':
			uso(argv[0]);
			break;
		case 'h':
		default:
			uso(argv[0]);
			break;
		}
	}

	return 0;
}
