
#include "stdafx.h"

#include <stdio.h>
#include <windows.h>

WCHAR *UrlDecodeWCHAR(WCHAR *String1)
{
	WCHAR *String2 = new WCHAR[wcslen(String1) - 1];
	int Flag = 0;

	for (int i = 0; i < wcslen(String1); i++)
	{
		if ((String1[i + Flag * 2] == L'%') && (String1[i + 1 + Flag * 2] == L'2'))
		{
			if (String1[i + 2 + Flag * 2] == L'0')
				String2[i] = L' ';
			else if (String1[i + 2 + Flag * 2] == L'2')
				String2[i] = L'\"';
			else if (String1[i + 2 + Flag * 2] == L'7')
				String2[i] = L'\'';
			else
				continue;
			Flag++;
		}
		else
		{
			String2[i] = String1[i + Flag * 2];
		}
	}
	//	printf("%ws", String2);
	return String2;
}

char *UrlDecodeChar(char *String1)
{
	char *String2 = new char[strlen(String1) - 1];
	int Flag = 0;

	for (int i = 0; i < strlen(String1); i++)
	{
		if ((String1[i + Flag * 2] == '%') && (String1[i + 1 + Flag * 2] == '2'))
		{
			if (String1[i+2 + Flag * 2] == '0')
				String2[i] = ' ';
			else if (String1[i + 2 + Flag * 2] == '2')
				String2[i] = '\"';
			else if (String1[i + 2 + Flag * 2] == '7')
				String2[i] = '\'';
			else
				continue;
			Flag++;
		}
		else
		{
			String2[i] = String1[i + Flag * 2];
		}
	}
//	printf("%s", String2);
	return String2;
}

int main()
{
	WCHAR *a = L"ab%22cd%20ef%27gh";
	WCHAR *b = UrlDecodeWCHAR(a);
	printf("%ws\n", b);
	
	char *c = "ab%22cd%20ef%27gh";	
	char *d = UrlDecodeChar(c);
	printf("%s\n", d);

	return 0;
}
