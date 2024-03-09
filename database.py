"""
created by Yoav Kolet
"""

import pickle
import os


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


class Database(DatabaseDict):
    def __init__(self):
        super().__init__()
        self.path = "C://Driver assets//database.pkl"
        try:
            open(self.path, "w").close()
        except FileNotFoundError:
            os.mkdir("C://Driver assets//")
            open(self.path, "w").close()
        self.__read_data__()

    def set_value(self, key, val):  # critical code
        self.__read_data__()
        super().set_value(key, val)
        self.__write_data__()

    def get_value(self, key):
        self.__read_data__()
        return super().get_value(key)

    def remove_value(self, key):  # critical code
        self.__read_data__()
        super().remove_value(key)
        self.__write_data__()

    def __write_data__(self):  # critical code
        with open(self.path, "wb") as file:
            pickle.dump(self.data, file)

    def __read_data__(self):
        with open(self.path, "rb") as file:
            data = file.read()
            if data != b"":
                self.data = pickle.loads(data)
            file.close()


def main():
    db = Database()
    db.set_value("yoav", 100)
    db.set_value("ido", 2)
    db.set_value("ohad", 1000)
    print(db)

    db.remove_value("ohad")
    print(db)

    print(db.get_value("yoav"))
    db.remove_value("yoav")
    db.remove_value("ido")
    print(db)


if __name__ == '__main__':
    main()
