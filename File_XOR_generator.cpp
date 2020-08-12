
#include "stdafx.h"
int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("File_XOR_generator\n");
		printf("Usage:\n");
		printf("%s <file path> <XOR inputs>\n", argv[0]);
		printf("Eg:\n");
		printf("%s test.exe 0x01\n", argv[0]);

		return 0;
	}

	int x;
	sscanf_s(argv[2], "%x", &x);

	FILE* fp;
	int err = fopen_s(&fp, argv[1], "ab+");
	if (err != 0)
	{
		printf("\n[!]Open file error");
		return 0;
	}
	fseek(fp, 0, SEEK_END);
	int len = ftell(fp);
	unsigned char *buf = new unsigned char[len];
	fseek(fp, 0, SEEK_SET);
	fread(buf, len, 1, fp);
	fclose(fp);
	printf("[*] file name:%s\n", argv[1]);
	printf("[*] file size:%d\n", len);

	for (int i = 0; i < len; i++)
	{
		buf[i] = buf[i]^ x;
	}
	char strNew[256] = {0};
	snprintf(strNew, 256, "xor_%s", argv[1]);

	FILE* fp2;
	err = fopen_s(&fp2, strNew, "wb+");
	if (err != 0)
	{
		printf("\n[!]createfile error!");
		return 0;
	}
	fwrite(buf, len, 1, fp2);
	fclose(fp2);
	
	printf("[*] XOR file name:%s\n", strNew);
	printf("[*] XOR file size:%d\n", len);
}

