#include <idc.idc>
//crypted data  size need input.

static Decrypt(cur, size)
{
	auto key_address = 0x10007B20;
	auto key_size = 0xB;
	auto uIndex = 0;
	auto value, i, key_value;
	for (i = 0; i < size; ++i)
	{
		value = Byte(cur+i);
		uIndex = i % 0xB;		//get remainder.
		key_value = Byte(key_address+uIndex);
		value = value ^ key_value;
		//Message("%s\n", value);
		PatchByte(cur+i, value);
	}
	return 1;
}
static getSize()
{
	auto  input;

	input = AskLong(00, "Input Crypted size:");

	Message("size: %x\n", input);
	return input;
}
static MyDecryptFunc()
{
	auto dataSize, curLine, ret;
	curLine = ScreenEA();
	dataSize = getSize();
	ret = Decrypt(curLine, dataSize);
	
	if (ret)
		Message("ok\n");
	else
		Message("fail\n");

}

static main()
{
	AddHotkey("z", "MyDecryptFunc");

}

