struct MyStruct {
  int a;
  int b;
  char c;
};

union MyUnion {
  int asInt;
  char asChar;
  float* asFloatPointer;
};

enum MyEnum { EnumA, EnumB };

typedef struct MyStruct MyStructAlias;

typedef union MyUnion MyUnion;

MyStructAlias a;

typedef int (*compare_function)(int a, int b);

void MyFunction(MyStructAlias* aaa, int myArray[], MyUnion uni,
                unsigned int myUnsInt, enum MyEnum enum11,
                compare_function comp) {
  return;
}

int sum(int x, int y) {
  int x1 = 1;
  int x2 = 2;
  int list[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  return x + y + x1 + x2;
}

void voidFunction(int a, char b) {
  char myCharArray[10];
  a = a + 1;
}


int main(int argc, char const* argv[]) {
  int a = 1;
  sum(a, a);
  voidFunction(1, 'c');
  return 0;
}
