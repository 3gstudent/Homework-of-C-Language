
#include "stdafx.h"

#include <stdio.h>
#include <windows.h>

char *TextToHtml(char *String1) 
{
	char *String2 = new char[(strlen(String1) - 1)*5];
	int Flag = 0;
	for (int i = 0; i < strlen(String1); i++)
	{
		if (String1[i] == '\n')
		{
			String2[i + Flag*4] = '<';
			String2[i+1 + Flag * 4] = '/';
			String2[i + 2 + Flag * 4] = 'b';
			String2[i + 3 + Flag * 4] = 'r';
			String2[i + 4 + Flag * 4] = '>';
			Flag++;		
		}
		else
			String2[i + Flag * 4] = String1[i];

	}
	String2[strlen(String1) + Flag * 4] = '\0';
	return String2;
}

int main()
{
	char *a = "ab\ncd\nef\ngh\n";
	printf("%s\n", a);
	char *b = TextToHtml(a);
	printf("%s\n", b);
	return 0;
}
