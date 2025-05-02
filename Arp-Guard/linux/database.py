import os.path
import re


class Database:
    def __init__(self):
        super().__init__()
        self.dir = "/var/lib/ArpGuard"
        self.path = "/var/lib/ArpGuard/blocked_macs.txt"
        self.create_files()
        self.__read_data__()
        self.data = ""
        self.mac_address_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'

    def create_files(self):
        """
       Create a directory and a text file if they do not already exist.

       This method checks if the directory specified by the `dir` attribute exists.
       If it does not exist, it creates the directory using `os.makedirs`.
       It then checks if the text file specified by the `path` attribute exists.
       If it does not exist, it creates the file using `open` with mode "w".

       """
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)
        if not os.path.exists(self.path):
            open(self.path, "w")

    def set_value(self, val: str):  # critical code
        """
        Set a value in the data and write it to the file.

        This method first checks if the provided value matches the MAC address pattern using regular expression.
        If the value does not match the pattern, the method returns False.

        Then, it reads the existing data from the file using the private method `__read_data__`.
        If the value is not already in the data, it appends the value to the data string.

        Finally, it writes the updated data to the file using the private method `__write_data__`.

        :param val: The value (MAC address) to be set.
        :return: True if the value was successfully set and written to the file, False otherwise.
        """
        if not re.match(self.mac_address_pattern, val):
            return False

        self.__read_data__()
        if val not in self.data:
            self.data += val + "\r\n"
        self.__write_data__()
        return True

    def get_data(self):
        """
        Retrieve the data from the file.

        This method reads the data from the file using the private method `__read_data__`.
        """
        self.__read_data__()

    def remove_value(self, val):  # critical code
        """
        Remove a specified value from the data.

        This method reads the data from the file using the private method `__read_data__`, removes the specified value,
        and writes the updated data back to the file using the private method `__write_data__`.

        :param val: The value to be removed from the data.
        """
        self.__read_data__()
        self.data = "".join(self.data.split(val + "\r\n"))
        self.__write_data__()

    def clear_data(self):
        self.data = ""
        self.__write_data__()

    def __write_data__(self):  # critical code
        """
        Write the data to the file.

        This method writes the data stored in the class attribute `data` to the file specified by the class attribute `path`.

        Note: This method is intended for internal use only.

        """
        with open(self.path, "wb") as file:
            file.write(self.data.encode())
            file.close()

    def __read_data__(self):
        """
       Read the data from the file.

       This method reads the data from the file specified by the class attribute `path` and stores it in the class attribute `data`.

       Note: This method is intended for internal use only.

       """
        with open(self.path, "rb") as file:
            self.data = file.read().decode()
            file.close()

    def __repr__(self):
        return "database:\r\n" + self.data
