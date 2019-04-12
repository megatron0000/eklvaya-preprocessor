#include <stdio.h>
#include <unistd.h>


void empty_function() {

}

int main(int argc, char const *argv[]) {
	printf("RUID=%d\n", getuid());
	printf("EUID=%d\n", geteuid());
	int result = open("/tmp/x", 0);
	printf("Permission=%d\n", result);
	empty_function();
	return 0; 
}

int unused_function(int x, int y) {
	return x + y;
}

void another_unused_function(char c) {
	return;
}