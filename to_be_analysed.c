int sum(int x, int y) {
	int x1 = 1;
	int x2 = 2;
	int list[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	return x + y + x1 + x2;
}

void voidFunction(int a, char b) {
  a = a+1;
}

int main(int argc, char const *argv[]) {
	int a = 1;
	sum(a, a);
  voidFunction(1, 'c');
	return 0; 
}
