from winreg import *


class RegistryDatabase:
    def __init__(self):
        self.main_key = HKEY_CURRENT_USER
        self.key = "Software\\"
        self.sub_key = "ArpGuard"

        self.registry = self.create_reg()

    def create_reg(self):
        with OpenKey(self.main_key, self.key) as key:
            return CreateKey(key, self.sub_key)

    def set_value(self, sub_key, value):
        SetValue(self.registry, sub_key, REG_SZ, value)

    def __repr__(self):
        ret = "registry: \r\n"
        for i in range(0, QueryInfoKey(self.registry)[0]):
            ret += EnumKey(self.registry, i) + "\r\n"
        return ret


try:
    rdb = RegistryDatabase()

except Exception as e:
    print(f"Error: {e}")