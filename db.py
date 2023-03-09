import datetime
import random
import time
import logging

import sqlalchemy.exc
from sqlalchemy import select, update, create_engine, func, or_, delete
from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import desc, true
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql import Insert
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, create_engine, LargeBinary, Float
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.sql.expression import column
from sqlalchemy.sql.schema import ForeignKey
from sqlalchemy_utils import create_database, database_exists
from sqlalchemy.engine import Engine
from sqlalchemy import event
from dataset_orm import Binary, Function, Line, Base, init_clean_database, RVA

class Dataset_DB:
    """ manager for db query and connection """

    def __init__(self, db_addr):
        self.db_addr = db_addr
        self.engine = create_engine(db_addr, echo=False,
                                    pool_pre_ping=True
                                    )

    def shutdown(self):
        """ Close DB connection """
        self.engine.dispose()

    def find_binary(self, github_url=None, file_name=None, platform=None, build_mode=None, toolset_version=None, optimization=None):
        with Session(self.engine) as session:
            query = select(Binary).where(github_url=github_url,
                                         file_name=file_name,
                                         platform=platform,
                                         build_mode=build_mode,
                                         toolset_version=toolset_version,
                                         optimization=optimization)
            result = session.execute(query).first()
            statuses = []
            for _s in result:
                statuses.append(_s[0])
            return statuses

    def get_binary_by_id(self, bin_id):
        with Session(self.engine) as session:
            query = select(Binary).where(Binary.id == bin_id)
            result = session.execute(query).first()
            return result[0].path

    def add_binary(self, github_url, file_name, platform, build_mode, pushed_at, toolset_version, optimization, path, size):
        with Session(self.engine) as session:
            new_binary = Binary(github_url=github_url,
                                file_name=file_name,
                                platform=platform,
                                path=path,
                                build_mode=build_mode,
                                toolset_version=toolset_version,
                                pushed_at=pushed_at,
                                optimization=optimization,
                                size=size)
            session.add(new_binary)
            session.commit()
            return new_binary.id

    def bulk_add_binaries(self, binaries):
        """ used to import lot of repos at a time """
        if not binaries:
            return []
        binaries_objs = [Binary(**msg) for msg in binaries]
        with Session(self.engine) as session:
            session.bulk_save_objects(binaries_objs, return_defaults=True)
            session.commit()
        return binaries_objs

    def add_function(self, name, source_file, intersect_ratio, rvas, binary_id):
        with Session(self.engine) as session:
            new_function = Function(name=name,
                                    source_file=source_file,
                                    intersect_ratio=intersect_ratio,
                                    rvas=rvas,
                                    binary_id=binary_id)
            session.add(new_function)
            session.commit()
            return new_function.id

    def bulk_add_functions(self, functions):
        """ used to import lot of repos at a time """
        if not functions:
            return []
        functions_objs = [Function(**msg) for msg in functions]
        with Session(self.engine) as session:
            session.bulk_save_objects(functions_objs, return_defaults=True)
            session.commit()
        return functions_objs

    def bulk_add_rvas(self, rvas):
        """ used to import lot of repos at a time """
        if not rvas:
            return []
        rva_db_objs = [RVA(**msg) for msg in rvas]
        with Session(self.engine) as session:
            session.bulk_save_objects(rva_db_objs, return_defaults=True)
            session.commit()
        return rva_db_objs

    def add_line(self, line_number, rva, length, source_code, function_id):
        with Session(self.engine) as session:
            new_line = Line(line_number=line_number,
                            rva=rva,
                            length=length,
                            source_code=source_code,
                            function_id=function_id)
            session.add(new_line)
            session.commit()
            return new_line.id

    def bulk_add_lines(self, lines):
        """ used to import lot of repos at a time """
        if not lines:
            return []
        objs = [Line(**msg) for msg in lines]
        with Session(self.engine) as session:
            session.bulk_save_objects(objs, return_defaults=True)
            session.commit()
        return objs

    def delete_binary(self, binary_id):
        with Session(self.engine) as session:
            q = delete(Binary).where(Binary.id == binary_id)
            session.execute(q)
            session.commit()

    def init(self):
        init_clean_database(self.db_addr)