
// peinfo.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CpeinfoApp:
// �йش����ʵ�֣������ peinfo.cpp
//

class CpeinfoApp : public CWinAppEx
{
public:
	CpeinfoApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CpeinfoApp theApp;