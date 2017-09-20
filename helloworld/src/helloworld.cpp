#include<iostream>
#include<tuple>

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

template <typename T> void foreach(const T& t) {
	cout << std::get<t>(tp) << endl;
}


template <typename First, typename... Rest> void foreach(const First& first, const Rest&... rest) {
    //cout << first << ", ";
	cout << std::get<first>(tp) << ", ";
	foreach(rest...);
    //print(rest...); // recursive call using pack expansion syntax
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
#endif
	foreach(LIST);
}

