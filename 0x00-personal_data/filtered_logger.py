#!/usr/bin/env python3
""" Tasks -> Regex-ing """
import mysql.connector
import logging
import os
import re
from typing import List, Tuple


def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 separator: str) -> str:
    """ Returns the log msg obfuscated by replacing field vals """
    ptrn = r"({})=[^{}]*".format('|'.join(fields), separator)
    return re.sub(ptrn, lambda match: "{}={}".format(
        match.group(1),
        redaction),
        message)


PII_FIELDS: Tuple[str, str, str, str, str] = ("name", "email", "phone",
                                              "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ Init the RedactingFormatter with the given fields """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:

        """ Format the log record to redact sensitive data """
        msg = super().format(record)
        output = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return output


def get_logger() -> logging.Logger:
    """ Creates and returns a logger configuree with RedactingFormatter """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Connect to the MySQL db using env vars and returns the cnx obj """
    usr = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    pwd = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db = os.getenv('PERSONAL_DATA_DB_NAME', '')

    if not db:
        raise ValueError("The DB_name not specified in PERSONAL_DATA_DB_NAME")

    db_con = mysql.connector.connect(
            user=usr,
            port=3306,
            password=pwd,
            host=host,
            database=db,)
    return db_con


def main() -> None:
    """ Function to retrieve and filter data from database """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users;")
    for row in cursor:
        msg = "; ".join("{}={}".format(k, v) for k, v in row.items())
        logger.info(msg)
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
