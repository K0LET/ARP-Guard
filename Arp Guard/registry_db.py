from winreg import *


class DatabaseDict:
    def __init__(self):
        self.data = {}

    def set_value(self, key, val):
        self.data[key] = val

    def get_value(self, key):
        if key in self.data:
            return self.data[key]
        return None

    def remove_value(self, key):
        if not self.get_value(key):
            print("cant remove value that doesnt exist")
            return False
        self.data.pop(key)
        return True

    def __repr__(self):
        return "database " + str(self.data)


class RegistryDatabase(DatabaseDict):
    def __init__(self):
        super().__init__()
        self.main_key = HKEY_CURRENT_USER
        self.key = "Software\\"
        self.sub_key = "ArpGuard"

        self.registry = self.create_reg()

    def create_reg(self):
        with OpenKey(self.main_key, self.key) as key:
            return CreateKey(key, self.sub_key)

    def set_value(self, sub_key, value):
        self.set_value(sub_key, value)
        SetValue(self.registry, sub_key, REG_SZ, value)

    def read_reg(self):
        for i in range(0, QueryInfoKey(self.registry)[0]):
            key = EnumKey(self.registry, 0)
            value = QueryValue(self.registry, key)
            self.set_value()

    def __repr__(self):
        ret = "registry: \r\n"
        for i in range(0, QueryInfoKey(self.registry)[0]):
            key = EnumKey(self.registry, 0)
            value = QueryValue(self.registry, key)
            ret += f"{key} - {value}" + "\r\n"
        return ret


try:
    rdb = RegistryDatabase()
    print(rdb)

except Exception as e:
    print(f"Error: {e}")