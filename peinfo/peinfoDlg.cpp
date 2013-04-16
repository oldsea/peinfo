
// peinfoDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "peinfo.h"
#include "peinfoDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CpeinfoDlg �Ի���




CpeinfoDlg::CpeinfoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CpeinfoDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CpeinfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CpeinfoDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_OPENFILE, &CpeinfoDlg::OnBnClickedOpenfile)
END_MESSAGE_MAP()


// CpeinfoDlg ��Ϣ�������

BOOL CpeinfoDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CpeinfoDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CpeinfoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CpeinfoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CpeinfoDlg::OnBnClickedOpenfile()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	OPENFILENAME opf;
	memset(&opf, 0, sizeof(opf));
	opf.lStructSize = sizeof(opf);
	opf.hwndOwner = this->m_hWnd;
	opf.lpstrFilter = L"exe file\0*.exe\0;All Files\0*.*\0";
	WCHAR szFileName[MAX_PATH];
	memset(szFileName,0,MAX_PATH);
	opf.lpstrFile = szFileName;
	opf.nMaxFile = MAX_PATH;
	opf.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	GetOpenFileName(&opf);

	CWnd* CtrlFileName = GetDlgItem(IDC_EDIT_FILENAME);
	CtrlFileName->SetWindowText(szFileName);

	//�򿪲�����map�ļ�
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if (dwFileSize)
		{
			HANDLE hMapFile = CreateFileMapping(hFile,NULL, PAGE_READONLY, 0, 0, NULL);
			LPVOID lpMemory = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
			//���PE�ļ��Ƿ���Ч
			if (lpMemory)
			{
				IMAGE_DOS_HEADER* pDosHead;
				pDosHead = (IMAGE_DOS_HEADER*) lpMemory;
				if ((unsigned short)(pDosHead->e_magic) != IMAGE_DOS_SIGNATURE)
				{
					MessageBox(L"not dos head!");
					goto PROC_ERROR_PE_FILE;
					//return;
				}
				IMAGE_NT_HEADERS* pNtHead;
				pNtHead =(IMAGE_NT_HEADERS*)((DWORD)pDosHead + (DWORD)pDosHead->e_lfanew);
				if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
				{
					MessageBox(L"not NT HEAD!");
					goto PROC_ERROR_PE_FILE;
					//return;
				}
				ProcessPeFile(lpMemory, pNtHead, dwFileSize);
			PROC_ERROR_PE_FILE:
				UnmapViewOfFile(lpMemory);
			}
			CloseHandle(hMapFile);
		}
		CloseHandle(hFile);
	}
}

void CpeinfoDlg::ProcessPeFile(LPVOID lpMemory, IMAGE_NT_HEADERS* pNtHead, DWORD dwFileSize)
{
	CString csFileName;
	CWnd* CtrlFileName = GetDlgItem(IDC_EDIT_FILENAME);
	CtrlFileName->GetWindowText(csFileName);
	WORD wMachine = pNtHead->FileHeader.Machine;
	WORD wNumSections = pNtHead->FileHeader.NumberOfSections;
	WORD wCharact = pNtHead->FileHeader.Characteristics;

	WCHAR cbHeadInfo[1024];
	wsprintf(cbHeadInfo,L"�ļ�����%s\r\n-----------------------------------------------------------------\r\n\
		                 \r\n����ƽ̨��       0x%04x\r\n����������       %d\r\n�ļ���ǣ�       0x%04x\r\n����װ���ַ��      0x%08x\r\n",
						csFileName, wMachine, wNumSections, wCharact, pNtHead->OptionalHeader.ImageBase);
	
	CWnd* CtrlFileInfo = GetDlgItem(IDC_EDIT_PEINFO);
	CtrlFileInfo->SetWindowText(cbHeadInfo);
	
	CString strSectorHeaderText = L"�������� ������С  �����ַ  RAW_�ߴ�  RAW_ƫ��  ��������\r\n";

	IMAGE_SECTION_HEADER* pSectorHeader = (IMAGE_SECTION_HEADER*)((DWORD)pNtHead+sizeof(IMAGE_NT_HEADERS));
	CHAR szSectionName[16];
	CHAR szSectionInfo[100];
	CString str;
	for (int i=0; i<wNumSections; i++)
	{
		memset(szSectionName, 0, 16);
		memset(szSectionInfo, 0, 100);
		char* pch = (char*)pSectorHeader;
		int j =0;
		for (j=0; j<8; j++)
		{
			if (*(char*)(pch+j) != '\0')
			{
				szSectionName[j] = *(char*)(pch+j);
			}
		}
		szSectionName[j] = '\0';
		wsprintfA(szSectionInfo,"%s  %08x  %08x  %08x  %08x  %08x\r\n", szSectionName, pSectorHeader->Misc.VirtualSize, pSectorHeader->VirtualAddress, pSectorHeader->SizeOfRawData, pSectorHeader->PointerToRawData,pSectorHeader->Characteristics);
		str+=szSectionInfo;
		pSectorHeader = (IMAGE_SECTION_HEADER*)((DWORD)pSectorHeader + sizeof(IMAGE_SECTION_HEADER));
	}

	CString strPeContent;
	strPeContent.Append(cbHeadInfo);
	strPeContent.Append(strSectorHeaderText);
	strPeContent.Append(str);
	CtrlFileInfo->SetWindowText(strPeContent);

	//std::string strPeContent;

}
