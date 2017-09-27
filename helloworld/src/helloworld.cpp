#include<iostream>
#include<tuple>
#include<memory>

#include<openssl/dsa.h>
#include<openssl/err.h>
#include<openssl/md5.h>
#include<openssl/bn.h>

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

