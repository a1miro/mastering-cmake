#include<iostream>
#include<tuple>
#include<memory>

#include<openssl/dsa.h>
#include<openssl/err.h>
#include<openssl/md5.h>
#include<openssl/bn.h>
#include<openssl/ec.h>
#include<openssl/ecdh.h>
#include<openssl/evp.h>
#include<openssl/crypto.h>

using namespace std;

#define LIST A,B,C,D
#define STRING_TYPES  string, string, string, string


enum STRINGS
{
	LIST
};


std::tuple<STRING_TYPES>tp = std::make_tuple<STRING_TYPES>("A", "B", "C", "D" );

void print() {
    cout << endl;
}


template <typename T> void print(const T& t) {
	cout << t << endl;

	//cout << std::get<0>(tp) << endl;
}


template <typename First, typename... Rest> void print(const First& first, const Rest&... rest) {
    cout << first << ", ";
	//cout << std::get<first>(tp) << ", ";

    print(rest...); // recursive call using pack expansion syntax
}

using DSA_SIG_ptr = std::unique_ptr<DSA_SIG, std::function<void(DSA_SIG*)>>;
using DSA_ptr = std::unique_ptr<DSA, std::function<void(DSA*)>>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, function<void(BN_CTX*)>>;
using BN_ptr = std::unique_ptr<BIGNUM, function<void(BIGNUM*)>>;

unsigned char message_hash[16];
string message("Hello world!");

DSA_ptr dsa(
		DSA_generate_parameters(1024, NULL, 0, NULL, NULL, NULL, NULL),
		DSA_free);

void md5()
{
	MD5_CTX hash_ctx;
	MD5_Init(&hash_ctx); // initialize
	MD5_Update(&hash_ctx, message.c_str(), message.size()); // update
	MD5_Final(message_hash, &hash_ctx); // compute the hash vla
}
void dump(DSA* dsa)
{
	cout << "dsa->p:" << endl;
	cout << BN_bn2dec(dsa->p) << endl;

	cout << "dsa->g:" << endl;
	cout << BN_bn2dec(dsa->g) << endl;

	cout << "dsa->q:" << endl;
	cout << BN_bn2dec(dsa->q) << endl;

	cout << "dsa->pub_key:" << endl;
	cout << BN_bn2dec(dsa->pub_key) << endl;

	cout << "dsa->priv_key:" << endl;
	cout << BN_bn2dec(dsa->priv_key) << endl;

	cout << "dsa->kinv:" << endl;
	cout << BN_bn2dec(dsa->kinv) << endl;

	cout << "dsa->r:" << endl;
	if (dsa->r)
		cout << BN_bn2dec(dsa->r) << endl;
	else
		cout << "NOT DEFINED!" << endl;
}

void dump_sig(DSA_SIG* dsa_sig)
{
	cout << "dsa_sig->r:" << endl;
	cout << BN_bn2dec(dsa_sig->r) << endl;

	cout << "dsa_sig->s:" << endl;
	cout << BN_bn2dec(dsa_sig->s) << endl;
}


void sign()
{
	DSA_generate_key(dsa.get());
	BN_CTX_ptr ctx(BN_CTX_new(), BN_CTX_free);
	BIGNUM* r = NULL;
	DSA_sign_setup(dsa.get(), ctx.get(), &dsa->kinv, &r);

	dump(dsa.get());

	DSA_SIG_ptr dsa_sig(DSA_do_sign(message_hash,16,dsa.get()), DSA_SIG_free);
	if (!dsa_sig)
	{
		cout << "DSA_do_sign has failed!" << endl;
	}

	cout << endl;
	dump_sig(dsa_sig.get());
}

BN_ptr v(BN_new(),BN_free);
void calculate_v()
{

}

void handleErrors()
{
	cout << "Error ...." << endl;
}

EC_GROUP* create_curve(void) {
	BN_CTX *ctx;
	EC_GROUP *curve;
	BIGNUM *a, *b, *p, *order, *x, *y;
	EC_POINT *generator;

	/* Binary data for the curve parameters */
	unsigned char a_bin[28] =
	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE};
	unsigned char b_bin[28] =
	{0xB4,0x05,0x0A,0x85,0x0C,0x04,0xB3,0xAB,0xF5,0x41,
			0x32,0x56,0x50,0x44,0xB0,0xB7,0xD7,0xBF,0xD8,0xBA,
			0x27,0x0B,0x39,0x43,0x23,0x55,0xFF,0xB4};
	unsigned char p_bin[28] =
	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
	unsigned char order_bin[28] =
	{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0x16,0xA2,0xE0,0xB8,0xF0,0x3E,
			0x13,0xDD,0x29,0x45,0x5C,0x5C,0x2A,0x3D };
	unsigned char x_bin[28] =
	{0xB7,0x0E,0x0C,0xBD,0x6B,0xB4,0xBF,0x7F,0x32,0x13,
			0x90,0xB9,0x4A,0x03,0xC1,0xD3,0x56,0xC2,0x11,0x22,
			0x34,0x32,0x80,0xD6,0x11,0x5C,0x1D,0x21};
	unsigned char y_bin[28] =
	{0xbd,0x37,0x63,0x88,0xb5,0xf7,0x23,0xfb,0x4c,0x22,
			0xdf,0xe6,0xcd,0x43,0x75,0xa0,0x5a,0x07,0x47,0x64,
			0x44,0xd5,0x81,0x99,0x85,0x00,0x7e,0x34};

	/* Set up the BN_CTX */
	if(NULL == (ctx = BN_CTX_new())) handleErrors();

	/* Set the values for the various parameters */
	if(NULL == (a = BN_bin2bn(a_bin, 28, NULL))) handleErrors();
	if(NULL == (b = BN_bin2bn(b_bin, 28, NULL))) handleErrors();
	if(NULL == (p = BN_bin2bn(p_bin, 28, NULL))) handleErrors();
	if(NULL == (order = BN_bin2bn(order_bin, 28, NULL))) handleErrors();
	if(NULL == (x = BN_bin2bn(x_bin, 28, NULL))) handleErrors();
	if(NULL == (y = BN_bin2bn(y_bin, 28, NULL))) handleErrors();

	/* Create the curve */
	if(NULL == (curve = EC_GROUP_new_curve_GFp(p, a, b, ctx))) handleErrors();
	if(NULL == (curve = EC_GROUP_new_curve_GF2m(p, a, b, ctx))) handleErrors();

	/* Create the generator */
	if(NULL == (generator = EC_POINT_new(curve))) handleErrors();
	if(1 != EC_POINT_set_affine_coordinates_GFp(curve, generator, x, y, ctx))
		handleErrors();

	/* Set the generator and the order */
	if(1 != EC_GROUP_set_generator(curve, generator, order, NULL))
		handleErrors();

	EC_POINT_free(generator);
	BN_free(y);
	BN_free(x);
	BN_free(order);
	BN_free(p);
	BN_free(b);
	BN_free(a);
	BN_CTX_free(ctx);

	return curve;
}


unsigned char *ecdh_low(size_t *secret_len)
{
	EC_KEY *key, *peerkey;
	int field_size;
	unsigned char *secret;

	EC_POINT *pub;


	/* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
	if(NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) handleErrors();

	/* Generate the private and public key */
	if(1 != EC_KEY_generate_key(key)) handleErrors();

	/* Get the peer's public key, and provide the peer with our public key -
	 * how this is done will be specific to your circumstances */
	//peerkey = get_peerkey_low(key);

	/* Calculate the size of the buffer for the shared secret */
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	*secret_len = (field_size+7)/8;

	/* Allocate the memory for the shared secret */
	if(NULL == (secret = (unsigned char*)OPENSSL_malloc(*secret_len))) handleErrors();

	/* Derive the shared secret */
	*secret_len = ECDH_compute_key(secret, *secret_len, EC_KEY_get0_public_key(peerkey),
						key, NULL);

	/* Clean up */
	EC_KEY_free(key);
	EC_KEY_free(peerkey);

	if(*secret_len <= 0)
	{
		OPENSSL_free(secret);
		return NULL;
	}

	return secret;
}

int main() {
#if 0
	//print(); // calls first overload, outputting only a newline
	print(1); // calls second overload

	// these call the third overload, the variadic template,
	// which uses recursion as needed.
	print(10, 20);
	print(100, 200, 300);
	print("first", 2, "third", 3.14159);
	print(LIST);
#endif
	try{
		md5();
		sign();
	}
	catch (std::exception& e)
	{
		cout << "EXCEPTION!!!!" << endl;
		cout << e.what() << endl;
	}
}

