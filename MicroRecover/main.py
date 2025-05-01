import os
import sys
import win32file
import win32con
import psutil
from tqdm import tqdm
import time
import struct
import ctypes
from ctypes import wintypes
import binascii
from datetime import datetime
import uuid
from collections import defaultdict

# Constantes do Windows para acesso ao disco
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0
IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x2D1080

# Constantes para sistemas de arquivos
NTFS_SIGNATURE = b'NTFS    '
FAT32_SIGNATURE = b'FAT32   '
EXFAT_SIGNATURE = b'EXFAT   '

# Assinaturas de arquivos comuns
FILE_SIGNATURES = {
    # Imagens
    b'\xFF\xD8\xFF': '.jpg',
    b'\x89PNG\r\n\x1a\n': '.png',
    b'GIF87a': '.gif',
    b'GIF89a': '.gif',
    b'BM': '.bmp',
    b'II*\x00': '.tif',
    b'MM\x00*': '.tif',
    
    # Documentos
    b'%PDF-': '.pdf',
    b'PK\x03\x04': '.zip',
    b'PK\x05\x06': '.zip',
    b'Rar!\x1a\x07': '.rar',
    b'7F45 4C 46': '.elf',
    b'\x50\x4B\x03\x04': '.docx',
    b'\x50\x4B\x05\x06': '.docx',
    
    # Áudio/Video
    b'ID3': '.mp3',
    b'OggS': '.ogg',
    b'RIFF': '.wav',
    b'\x00\x00\x01\xBA': '.mpg',
    b'\x00\x00\x01\xB3': '.mpg',
    b'FLV': '.flv',
    b'fLaC': '.flac',
    
    # Outros
    b'<?xml': '.xml',
    b'<!DOCTYPE HTML': '.html',
    b'\xEF\xBB\xBF': '.txt',  # UTF-8 BOM
    b'\xFF\xFE': '.txt',      # UTF-16 LE
    b'\xFE\xFF': '.txt',      # UTF-16 BE
}

# Categorias de arquivos
FILE_CATEGORIES = {
    '.jpg': 'Imagens',
    '.png': 'Imagens',
    '.gif': 'Imagens',
    '.bmp': 'Imagens',
    '.tif': 'Imagens',
    '.pdf': 'Documentos',
    '.zip': 'Arquivos',
    '.rar': 'Arquivos',
    '.docx': 'Documentos',
    '.mp3': 'Música',
    '.ogg': 'Música',
    '.wav': 'Música',
    '.mpg': 'Vídeos',
    '.flv': 'Vídeos',
    '.xml': 'Documentos',
    '.html': 'Documentos',
    '.txt': 'Documentos',
}

class DirectoryEntry:
    def __init__(self, name, offset, size, attributes, parent=None):
        self.name = name
        self.offset = offset
        self.size = size
        self.attributes = attributes
        self.parent = parent
        self.children = []
        self.is_directory = (attributes & 0x10) == 0x10
        self.is_deleted = (attributes & 0x80) == 0x80

class FileSystem:
    def __init__(self):
        self.root = DirectoryEntry("/", 0, 0, 0x10)  # Root é um diretório
        self.categories = defaultdict(list)
        self.all_entries = []
        self.fs_type = None
    
    def detect_filesystem(self, buffer):
        """Detecta o tipo de sistema de arquivos"""
        if NTFS_SIGNATURE in buffer:
            self.fs_type = "NTFS"
            print("Sistema de arquivos NTFS detectado")
            return True
        elif FAT32_SIGNATURE in buffer:
            self.fs_type = "FAT32"
            print("Sistema de arquivos FAT32 detectado")
            return True
        elif EXFAT_SIGNATURE in buffer:
            self.fs_type = "exFAT"
            print("Sistema de arquivos exFAT detectado")
            return True
        return False
    
    def add_directory_entry(self, name, offset, size, attributes, parent=None):
        """Adiciona uma entrada de diretório"""
        entry = DirectoryEntry(name, offset, size, attributes, parent)
        if parent:
            parent.children.append(entry)
        self.all_entries.append(entry)
        return entry
    
    def add_file(self, offset, extension, size=0, name=None, parent=None):
        """Adiciona um arquivo"""
        if not name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"recovered_{timestamp}{extension}"
        
        # Determina a categoria do arquivo
        category = FILE_CATEGORIES.get(extension, "Outros")
        
        # Cria a entrada do arquivo
        entry = DirectoryEntry(name, offset, size, 0x20, parent)  # 0x20 = arquivo normal
        
        # Adiciona à categoria
        self.categories[category].append(entry)
        
        # Adiciona à estrutura de diretórios
        if parent:
            parent.children.append(entry)
        else:
            self.root.children.append(entry)
        
        self.all_entries.append(entry)
        return entry
    
    def display_structure(self):
        """Mostra a estrutura de arquivos encontrados"""
        print("\nEstrutura de arquivos encontrados:")
        print("=" * 50)
        self._display_directory(self.root, "")
    
    def _display_directory(self, directory, indent=""):
        """Mostra o conteúdo de um diretório recursivamente"""
        for entry in directory.children:
            size_str = ""
            if entry.size > 0:
                if entry.size >= 1024*1024*1024:
                    size_str = f"{entry.size/(1024*1024*1024):.2f} GB"
                elif entry.size >= 1024*1024:
                    size_str = f"{entry.size/(1024*1024):.2f} MB"
                elif entry.size >= 1024:
                    size_str = f"{entry.size/1024:.2f} KB"
                else:
                    size_str = f"{entry.size} bytes"
            
            status = "[D]" if entry.is_deleted else ""
            type_marker = "/" if entry.is_directory else ""
            print(f"{indent}{'└── ' if indent else ''}{entry.name}{type_marker} {status} {size_str}")
            
            if entry.is_directory:
                self._display_directory(entry, indent + "    ")

class Partition:
    def __init__(self, bootable, start_sector, size_sectors, type_code, name=""):
        self.bootable = bootable
        self.start_sector = start_sector
        self.size_sectors = size_sectors
        self.type_code = type_code
        self.name = name
        self.start_byte = start_sector * 512
        self.size_bytes = size_sectors * 512

class GPTHeader:
    def __init__(self, data):
        self.signature = data[0:8]
        self.revision = struct.unpack('<I', data[8:12])[0]
        self.header_size = struct.unpack('<I', data[12:16])[0]
        self.crc32 = struct.unpack('<I', data[16:20])[0]
        self.reserved = struct.unpack('<I', data[20:24])[0]
        self.current_lba = struct.unpack('<Q', data[24:32])[0]
        self.backup_lba = struct.unpack('<Q', data[32:40])[0]
        self.first_usable_lba = struct.unpack('<Q', data[40:48])[0]
        self.last_usable_lba = struct.unpack('<Q', data[48:56])[0]
        self.disk_guid = uuid.UUID(bytes_le=data[56:72])
        self.partition_entries_lba = struct.unpack('<Q', data[72:80])[0]
        self.num_partition_entries = struct.unpack('<I', data[80:84])[0]
        self.partition_entry_size = struct.unpack('<I', data[84:88])[0]
        self.partition_entries_crc32 = struct.unpack('<I', data[88:92])[0]

class FileValidator:
    @staticmethod
    def validate_jpeg(data):
        if len(data) < 2:
            return False
        if data[0:2] != b'\xFF\xD8':
            return False
        # Verifica se termina com FF D9
        if data[-2:] != b'\xFF\xD9':
            return False
        return True

    @staticmethod
    def validate_png(data):
        if len(data) < 8:
            return False
        if data[0:8] != b'\x89PNG\r\n\x1a\n':
            return False
        return True

    @staticmethod
    def validate_pdf(data):
        if len(data) < 5:
            return False
        if data[0:5] != b'%PDF-':
            return False
        return True

    @staticmethod
    def validate_zip(data):
        if len(data) < 4:
            return False
        if data[0:4] != b'PK\x03\x04':
            return False
        return True

    @staticmethod
    def validate_mp3(data):
        if len(data) < 3:
            return False
        # Verifica se começa com ID3 ou frame MP3
        if data[0:3] == b'ID3' or data[0:3] == b'\xFF\xFB':
            return True
        return False

class FileCarver:
    def __init__(self):
        self.fragments = {}  # Dicionário para armazenar fragmentos de arquivos
        self.max_fragment_gap = 1024 * 1024  # 1MB de gap máximo entre fragmentos
        
    def add_fragment(self, file_id, offset, data):
        if file_id not in self.fragments:
            self.fragments[file_id] = []
        self.fragments[file_id].append((offset, data))
        
    def try_reconstruct(self, file_id):
        if file_id not in self.fragments:
            return None
            
        fragments = self.fragments[file_id]
        fragments.sort(key=lambda x: x[0])  # Ordena por offset
        
        # Verifica se os fragmentos estão próximos o suficiente
        for i in range(len(fragments)-1):
            current_end = fragments[i][0] + len(fragments[i][1])
            next_start = fragments[i+1][0]
            if next_start - current_end > self.max_fragment_gap:
                return None  # Gap muito grande, não é possível reconstruir
                
        # Reconstrui o arquivo
        reconstructed = bytearray()
        for _, data in fragments:
            reconstructed.extend(data)
            
        return bytes(reconstructed)

class DiskReader:
    def __init__(self):
        self.sector_size = 512  # Tamanho padrão do setor
        self.buffer_size = 4096  # Tamanho do buffer de leitura
        self.partitions = []
        self.gpt_header = None
        self.file_system = FileSystem()
        self.current_drive = None
        self.current_partition = None
        self.carver = FileCarver()
        self.validators = {
            '.jpg': FileValidator.validate_jpeg,
            '.jpeg': FileValidator.validate_jpeg,
            '.png': FileValidator.validate_png,
            '.pdf': FileValidator.validate_pdf,
            '.zip': FileValidator.validate_zip,
            '.mp3': FileValidator.validate_mp3
        }
        self.min_file_sizes = {
            '.jpg': 100,  # 100 bytes
            '.jpeg': 100,
            '.png': 100,
            '.pdf': 100,
            '.zip': 100,
            '.mp3': 100
        }

    def validate_file(self, data, extension):
        if extension not in self.validators:
            return True  # Se não temos validador, aceita o arquivo
        
        if len(data) < self.min_file_sizes.get(extension, 0):
            return False
            
        return self.validators[extension](data)

    def format_hex_dump(self, data, offset=0):
        """Formata os dados em um dump hexadecimal legível"""
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_values = ' '.join(f'{b:02x}' for b in chunk)
            ascii_values = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            result.append(f'{offset+i:08x}  {hex_values:<48}  {ascii_values}')
        return '\n'.join(result)

    def parse_mbr(self, mbr_data):
        """Analisa o MBR e extrai informações das partições"""
        partitions = []
        
        # Verifica a assinatura do MBR (55 AA)
        if mbr_data[510] != 0x55 or mbr_data[511] != 0xAA:
            print("AVISO: Assinatura MBR inválida!")
            return partitions
        
        # Analisa as 4 entradas da tabela de partições
        for i in range(4):
            offset = 446 + (i * 16)
            entry = mbr_data[offset:offset+16]
            
            # Extrai informações da partição
            bootable = entry[0] == 0x80
            start_sector = struct.unpack('<I', entry[8:12])[0]
            size_sectors = struct.unpack('<I', entry[12:16])[0]
            type_code = entry[4]
            
            if type_code != 0:  # Partição válida
                partition = Partition(bootable, start_sector, size_sectors, type_code)
                partitions.append(partition)
                
                # Se for uma partição GPT (0xEE), tenta ler a GPT
                if type_code == 0xEE:
                    print("\nDetectada partição GPT. Tentando ler a tabela GPT...")
                    try:
                        # Lê o cabeçalho da GPT (setor 1)
                        gpt_header_data = self.read_sector(1)
                        if gpt_header_data:
                            # Converte o buffer para bytes
                            gpt_header_bytes = bytes(gpt_header_data)
                            self.gpt_header = GPTHeader(gpt_header_bytes)
                            print("Cabeçalho GPT encontrado!")
                            print(f"  Número de partições: {self.gpt_header.num_partition_entries}")
                            print(f"  Tamanho de cada entrada: {self.gpt_header.partition_entry_size} bytes")
                            print(f"  LBA da tabela de partições: {self.gpt_header.partition_entries_lba}")
                            
                            # Lê a tabela de partições
                            partition_entries = self.read_partition_entries()
                            if partition_entries:
                                partitions.extend(partition_entries)
                    except Exception as e:
                        print(f"Erro ao ler GPT: {str(e)}")
        
        return partitions

    def read_partition_entries(self):
        """Lê as entradas da tabela de partições GPT"""
        if not self.gpt_header:
            return []
        
        partitions = []
        entries_per_sector = self.sector_size // self.gpt_header.partition_entry_size
        
        # Lê cada setor da tabela de partições
        for i in range(0, self.gpt_header.num_partition_entries, entries_per_sector):
            sector = self.read_sector(self.gpt_header.partition_entries_lba + (i // entries_per_sector))
            if not sector:
                break
            
            # Converte o buffer para bytes
            sector_bytes = bytes(sector)
            
            # Processa cada entrada no setor
            for j in range(entries_per_sector):
                if i + j >= self.gpt_header.num_partition_entries:
                    break
                
                offset = j * self.gpt_header.partition_entry_size
                entry = sector_bytes[offset:offset + self.gpt_header.partition_entry_size]
                
                # Extrai informações da partição
                type_guid = uuid.UUID(bytes_le=entry[0:16])
                unique_guid = uuid.UUID(bytes_le=entry[16:32])
                start_lba = struct.unpack('<Q', entry[32:40])[0]
                end_lba = struct.unpack('<Q', entry[40:48])[0]
                attributes = struct.unpack('<Q', entry[48:56])[0]
                name = entry[56:].decode('utf-16le').rstrip('\0')
                
                if start_lba != 0:  # Partição válida
                    partition = Partition(
                        bootable=(attributes & 1) != 0,
                        start_sector=start_lba,
                        size_sectors=end_lba - start_lba + 1,
                        type_code=0xEE,  # GPT
                        name=name
                    )
                    partitions.append(partition)
        
        return partitions

    def read_sector(self, sector_number):
        """Lê um setor específico do disco"""
        try:
            handle = win32file.CreateFile(
                f"\\\\.\\PhysicalDrive{self.current_drive}",
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_RANDOM_ACCESS,
                None
            )
            
            # Move para o setor desejado
            win32file.SetFilePointer(handle, sector_number * self.sector_size, win32file.FILE_BEGIN)
            
            # Lê o setor
            buffer = win32file.AllocateReadBuffer(self.sector_size)
            bytes_read = win32file.ReadFile(handle, buffer, None)
            
            handle.Close()
            return buffer
        except Exception as e:
            print(f"Erro ao ler setor {sector_number}: {str(e)}")
            return None

    def read_partition(self, partition_number):
        try:
            # Abre o disco físico para leitura
            handle = win32file.CreateFile(
                f"\\\\.\\PhysicalDrive{self.current_drive}",
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_RANDOM_ACCESS,
                None
            )
            
            try:
                # Cria um novo sistema de arquivos para a partição selecionada
                self.file_system = FileSystem()
                
                # Lê a partição específica
                selected_partition = self.partitions[partition_number-1]
                print(f"\nLendo partição: {selected_partition.name if selected_partition.name else 'Sem nome'}")
                print(f"Tamanho: {selected_partition.size_bytes / (1024*1024):.2f} MB")
                
                # Calcula o tamanho da partição em bytes
                partition_size = selected_partition.size_sectors * self.sector_size
                
                # Move para o início da partição
                print(f"\nMovendo para o início da partição: {selected_partition.start_byte} bytes")
                result = win32file.SetFilePointer(handle, selected_partition.start_byte, win32file.FILE_BEGIN)
                print(f"SetFilePointer retornou: {result}")
                
                offset = 0
                file_count = 0
                buffer_anterior = b''
                
                with tqdm(desc=f"Lendo partição {selected_partition.name if selected_partition.name else 'Sem nome'}", 
                         total=partition_size,
                         unit="B",
                         unit_scale=True) as pbar:
                    
                    while offset < partition_size:
                        try:
                            # Calcula quanto falta ler
                            bytes_to_read = min(self.buffer_size, partition_size - offset)
                            if bytes_to_read <= 0:
                                print("\nFim da partição alcançado")
                                break
                            
                            # Lê o próximo bloco
                            buffer = win32file.AllocateReadBuffer(bytes_to_read)
                            error, bytes_read = win32file.ReadFile(handle, buffer, None)
                            
                            if error != 0:
                                print(f"\nErro na leitura: {error}")
                                break
                                
                            if not bytes_read:
                                print("\nNenhum byte lido")
                                break
                            
                            # Converte o buffer para bytes
                            buffer_bytes = bytes(buffer[:len(bytes_read)])
                            
                            # Combina com o final do buffer anterior
                            combined_buffer = buffer_anterior[-32:] + buffer_bytes
                            
                            # Procura por assinaturas de arquivos
                            for signature, extension in FILE_SIGNATURES.items():
                                pos = 0
                                while True:
                                    pos = combined_buffer.find(signature, pos)
                                    if pos == -1:
                                        break
                                        
                                    # Ajusta a posição se a assinatura foi encontrada na parte do buffer anterior
                                    real_pos = pos - 32 if pos < 32 else pos - 32
                                    
                                    # Calcula a posição absoluta no disco
                                    abs_pos = selected_partition.start_byte + offset + real_pos
                                    
                                    # Tenta ler o arquivo completo
                                    file_data = buffer_bytes[real_pos:]
                                    file_size = self.estimate_file_size(file_data, extension)
                                    
                                    if file_size > 0:
                                        # Verifica se o arquivo está fragmentado
                                        if len(file_data) < file_size:
                                            # Adiciona como fragmento
                                            file_id = f"{abs_pos}_{extension}"
                                            self.carver.add_fragment(file_id, abs_pos, file_data)
                                            
                                            # Tenta reconstruir
                                            reconstructed = self.carver.try_reconstruct(file_id)
                                            if reconstructed:
                                                if self.validate_file(reconstructed, extension):
                                                    self.file_system.add_file(f"recovered_{file_count}{extension}", reconstructed)
                                                    file_count += 1
                                                    print(f"\nArquivo fragmentado recuperado: recovered_{file_count}{extension}")
                                        else:
                                            # Arquivo completo
                                            if self.validate_file(file_data[:file_size], extension):
                                                self.file_system.add_file(f"recovered_{file_count}{extension}", file_data[:file_size])
                                                file_count += 1
                                                print(f"\nArquivo encontrado: recovered_{file_count}{extension}")
                                    
                                    pos += len(signature)
                            
                            # Guarda o buffer atual para a próxima iteração
                            buffer_anterior = buffer_bytes
                            
                            # Atualiza a barra de progresso
                            pbar.update(len(bytes_read))
                            offset += len(bytes_read)
                            
                            # A cada 10MB lido, mostra um resumo
                            if offset % (10 * 1024 * 1024) == 0:
                                print(f"\nLidos {offset / (1024*1024):.2f} MB de {partition_size / (1024*1024):.2f} MB")
                                print(f"Arquivos encontrados até agora: {file_count}")
                            
                        except Exception as e:
                            print(f"\nErro durante a leitura no offset {offset}: {str(e)}")
                            print(f"Tipo do erro: {type(e)}")
                            import traceback
                            traceback.print_exc()
                            break
                
                print(f"\nLeitura da partição concluída!")
                print(f"Total de bytes lidos: {offset / (1024*1024):.2f} MB")
                print(f"Total de arquivos encontrados: {file_count}")
                
            finally:
                handle.Close()
                
        except Exception as e:
            print(f"Erro ao ler a partição: {str(e)}")
            print(f"Tipo do erro: {type(e)}")
            import traceback
            traceback.print_exc()
            return False
            
        return True

    def estimate_file_size(self, buffer, extension):
        """Tenta estimar o tamanho do arquivo baseado na extensão e conteúdo"""
        try:
            # Primeiro valida o arquivo se houver validador
            if extension in self.validators:
                if not self.validators[extension](buffer):
                    return 0  # Arquivo inválido
            
            # Procura por marcadores de fim específicos
            if extension in ['.jpg', '.jpeg']:
                # Procura pelo marcador de fim JPEG (FFD9)
                end_pos = buffer.find(b'\xFF\xD9')
                if end_pos != -1:
                    if end_pos < self.min_file_sizes[extension]:
                        return 0  # Muito pequeno para ser válido
                    return end_pos + 2
                    
            elif extension == '.png':
                # Procura pelo marcador de fim PNG (IEND)
                end_pos = buffer.find(b'IEND')
                if end_pos != -1:
                    if end_pos < self.min_file_sizes[extension]:
                        return 0
                    return end_pos + 8
                    
            elif extension == '.pdf':
                # Procura por %%EOF
                end_pos = buffer.find(b'%%EOF')
                if end_pos != -1:
                    if end_pos < self.min_file_sizes[extension]:
                        return 0
                    return end_pos + 5
                    
            elif extension in ['.zip', '.docx']:
                # Procura pelo diretório central do ZIP
                end_pos = buffer.find(b'PK\x05\x06')
                if end_pos != -1:
                    if end_pos < self.min_file_sizes[extension]:
                        return 0
                    return end_pos + 22
            
            # Se não encontrou o fim mas tem tamanho mínimo, usa o tamanho mínimo
            if extension in self.min_file_sizes:
                return self.min_file_sizes[extension]
            
        except Exception as e:
            print(f"Erro ao estimar tamanho do arquivo: {str(e)}")
        
        return 0  # Se não conseguiu determinar, considera inválido

    def list_physical_drives(self):
        """Lista todos os discos físicos disponíveis"""
        drives = []
        print("\nProcurando discos físicos...")
        
        # Tenta abrir cada disco físico até encontrar um que não existe
        index = 0
        while True:
            try:
                print(f"Tentando abrir PhysicalDrive{index}...")
                handle = win32file.CreateFile(
                    f"\\\\.\\PhysicalDrive{index}",
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_RANDOM_ACCESS,
                    None
                )
                
                # Se conseguiu abrir, tenta obter informações do disco
                try:
                    print(f"Obtendo geometria do disco {index}...")
                    # Tenta obter a geometria do disco
                    disk_geometry = win32file.DeviceIoControl(
                        handle,
                        IOCTL_DISK_GET_DRIVE_GEOMETRY,
                        None,
                        24
                    )
                    
                    # Calcula o tamanho total
                    cylinders, tracks_per_cylinder, sectors_per_track, bytes_per_sector = struct.unpack("QQQQ", disk_geometry)
                    total_size = cylinders * tracks_per_cylinder * sectors_per_track * bytes_per_sector
                    
                    print(f"Disco {index} encontrado! Tamanho: {total_size / (1024**3):.2f} GB")
                    drives.append({
                        'index': index,
                        'size': total_size,
                        'model': f"Disco Físico {index}"
                    })
                except Exception as e:
                    print(f"Erro ao obter geometria do disco {index}: {str(e)}")
                    # Tenta obter o tamanho de outra forma
                    try:
                        # Tenta ler o primeiro setor para verificar se o disco está acessível
                        buffer = win32file.AllocateReadBuffer(self.sector_size)
                        bytes_read = win32file.ReadFile(handle, buffer, None)
                        print(f"Disco {index} encontrado! (Tamanho não disponível)")
                        drives.append({
                            'index': index,
                            'size': 0,  # Tamanho desconhecido
                            'model': f"Disco Físico {index}"
                        })
                    except Exception as e2:
                        print(f"Disco {index} não está acessível: {str(e2)}")
                
                handle.Close()
                index += 1
            except Exception as e:
                print(f"Não foi possível abrir PhysicalDrive{index}: {str(e)}")
                break
        
        return drives

    def read_disk(self, drive_index):
        """Lê o conteúdo do disco físico"""
        print(f"\nLendo disco físico {drive_index}:")
        self.current_drive = drive_index
        
        try:
            # Abre o disco físico para leitura
            print(f"Abrindo PhysicalDrive{drive_index}...")
            handle = win32file.CreateFile(
                f"\\\\.\\PhysicalDrive{drive_index}",
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_RANDOM_ACCESS,
                None
            )
            
            try:
                # Tenta ler o primeiro setor para verificar se temos acesso
                print("Tentando ler o primeiro setor...")
                buffer = win32file.AllocateReadBuffer(self.sector_size)
                bytes_read = win32file.ReadFile(handle, buffer, None)
                print("Conseguimos ler o primeiro setor do disco!")
                print("\nConteúdo do primeiro setor:")
                print(self.format_hex_dump(buffer))
                
                # Analisa o MBR
                self.partitions = self.parse_mbr(buffer)
                
            except Exception as e:
                print(f"Erro ao ler o primeiro setor: {str(e)}")
            finally:
                handle.Close()
                return True
                
        except Exception as e:
            print(f"Erro ao acessar o disco: {str(e)}")
            return False

    def read_disk_content(self):
        """Lê o conteúdo do disco inteiro"""
        try:
            # Abre o disco físico para leitura
            handle = win32file.CreateFile(
                f"\\\\.\\PhysicalDrive{self.current_drive}",
                win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                win32con.FILE_FLAG_NO_BUFFERING | win32con.FILE_FLAG_RANDOM_ACCESS,
                None
            )
            
            try:
                offset = 0
                arquivos_encontrados = 0
                
                with tqdm(desc="Lendo disco", unit="B", unit_scale=True) as pbar:
                    while True:
                        try:
                            # Lê o próximo bloco
                            buffer = win32file.AllocateReadBuffer(self.buffer_size)
                            bytes_read = win32file.ReadFile(handle, buffer, None)
                            if bytes_read[0] == 0:  # EOF
                                break
                            
                            # Converte o buffer para bytes
                            buffer_bytes = bytes(buffer)
                            
                            # Procura por assinaturas de arquivos
                            for signature, extension in FILE_SIGNATURES.items():
                                pos = 0
                                while True:
                                    pos = buffer_bytes.find(signature, pos)
                                    if pos == -1:
                                        break
                                    
                                    # Verifica se encontrou uma assinatura válida
                                    print(f"\nEncontrada assinatura de {extension} em {offset + pos / (1024*1024):.2f} MB")
                                    
                                    # Valida o arquivo antes de adicionar
                                    if self.validate_file(buffer_bytes[pos:], extension):
                                        # Adiciona o arquivo à estrutura
                                        self.file_system.add_file(
                                            offset + pos,
                                            extension
                                        )
                                        arquivos_encontrados += 1
                                        pos += 1
                            
                            # Atualiza a barra de progresso
                            pbar.update(self.buffer_size)
                            offset += self.buffer_size
                            
                            # A cada 1MB lido, mostra um resumo
                            if offset % (1024 * 1024) == 0:
                                print(f"\nLidos {offset / (1024*1024):.2f} MB")
                                print(f"Arquivos encontrados até agora: {arquivos_encontrados}")
                            
                        except Exception as e:
                            print(f"\nErro durante a leitura: {str(e)}")
                            break
                
                print(f"\nLeitura concluída!")
                print(f"Total de arquivos encontrados: {arquivos_encontrados}")
                
            finally:
                handle.Close()
                
        except Exception as e:
            print(f"Erro ao acessar o disco: {str(e)}")
            return False
        
        return True

class UserInterface:
    def __init__(self):
        self.disk_reader = DiskReader()
        self.current_directory = "/"
        self.commands = {
            "help": self.show_help,
            "list": self.list_drives,
            "select": self.select_drive,
            "read": self.read_partition,
            "info": self.show_partition_info,
            "analyze": self.analyze_partition,
            "dir": self.list_directory,
            "ls": self.list_directory,
            "cd": self.change_directory,
            "tree": self.show_tree,
            "exit": self.exit_program
        }
        self.stats = {
            "total_files": 0,
            "valid_files": 0,
            "invalid_files": 0,
            "bytes_read": 0,
            "start_time": None
        }

    def show_partition_info(self, args=None):
        if not self.disk_reader.current_partition:
            print("Nenhuma partição selecionada.")
            return

        partition = self.disk_reader.current_partition
        print("\n=== Informações da Partição ===")
        print(f"Número: {partition.partition_number}")
        print(f"Tipo: {partition.partition_type}")
        print(f"Bootável: {'Sim' if partition.bootable else 'Não'}")
        print(f"Nome: {partition.partition_name}")
        print(f"Setor Inicial: {partition.start_sector}")
        print(f"Tamanho: {partition.size / (1024*1024):.2f} MB")
        
        if self.disk_reader.file_system:
            print("\n=== Arquivos Encontrados ===")
            print(f"Total: {self.stats['total_files']}")
            print(f"Válidos: {self.stats['valid_files']}")
            print(f"Inválidos: {self.stats['invalid_files']}")
            
            # Mostra os 5 maiores arquivos de cada categoria
            categories = {
                "Imagens": ['.jpg', '.jpeg', '.png', '.gif', '.bmp'],
                "Documentos": ['.pdf', '.doc', '.docx', '.txt'],
                "Vídeos": ['.mp4', '.avi', '.mkv'],
                "Músicas": ['.mp3', '.wav', '.ogg']
            }
            
            print("\n=== Maiores Arquivos por Categoria ===")
            for category, extensions in categories.items():
                print(f"\n{category}:")
                files = [f for f in self.disk_reader.file_system.get_all_files() 
                        if any(f.endswith(ext) for ext in extensions)]
                files.sort(key=lambda x: x.size, reverse=True)
                for f in files[:5]:
                    print(f"  {f.name} - {f.size / 1024:.2f} KB")

    def analyze_partition(self, args=None):
        if not self.disk_reader.current_partition:
            print("Nenhuma partição selecionada.")
            return

        print("\n=== Análise da Partição ===")
        
        # Distribuição temporal dos arquivos
        print("\nDistribuição Temporal:")
        files = self.disk_reader.file_system.get_all_files()
        if files:
            # Agrupa arquivos por faixa de tamanho
            size_ranges = {
                "0-1KB": 0,
                "1KB-10KB": 0,
                "10KB-100KB": 0,
                "100KB-1MB": 0,
                "1MB+": 0
            }
            
            for f in files:
                size_kb = f.size / 1024
                if size_kb < 1:
                    size_ranges["0-1KB"] += 1
                elif size_kb < 10:
                    size_ranges["1KB-10KB"] += 1
                elif size_kb < 100:
                    size_ranges["10KB-100KB"] += 1
                elif size_kb < 1024:
                    size_ranges["100KB-1MB"] += 1
                else:
                    size_ranges["1MB+"] += 1
            
            for range_name, count in size_ranges.items():
                print(f"  {range_name}: {count} arquivos")

        # Clusters de arquivos
        print("\nClusters de Arquivos:")
        if files:
            # Agrupa arquivos por extensão
            extensions = {}
            for f in files:
                ext = os.path.splitext(f.name)[1].lower()
                if ext not in extensions:
                    extensions[ext] = 0
                extensions[ext] += 1
            
            # Mostra as 10 extensões mais comuns
            common_exts = sorted(extensions.items(), key=lambda x: x[1], reverse=True)[:10]
            for ext, count in common_exts:
                print(f"  {ext}: {count} arquivos")

    def read_partition(self, args=None):
        if not self.disk_reader.current_drive:
            print("Nenhum drive selecionado.")
            return

        try:
            partition_number = int(args[0]) if args else None
            if partition_number is None:
                print("Número da partição não especificado.")
                return

            self.stats["start_time"] = time.time()
            self.stats["total_files"] = 0
            self.stats["valid_files"] = 0
            self.stats["invalid_files"] = 0
            self.stats["bytes_read"] = 0

            print(f"\nLendo partição {partition_number}...")
            success = self.disk_reader.read_partition(partition_number)
            
            if success:
                elapsed_time = time.time() - self.stats["start_time"]
                print(f"\nLeitura concluída em {elapsed_time:.2f} segundos")
                print(f"Total de arquivos encontrados: {self.stats['total_files']}")
                print(f"Arquivos válidos: {self.stats['valid_files']}")
                print(f"Arquivos inválidos: {self.stats['invalid_files']}")
                print(f"Bytes lidos: {self.stats['bytes_read'] / (1024*1024):.2f} MB")
                print("\nUse o comando 'info' para ver estatísticas detalhadas")
                print("Use o comando 'analyze' para ver análise da partição")
            else:
                print("Erro ao ler a partição.")

        except Exception as e:
            print(f"Erro ao ler partição: {str(e)}")

    def list_directory(self, args=None):
        """Lista o conteúdo do diretório atual"""
        if not self.disk_reader.file_system:
            print("Nenhuma partição selecionada. Use 'back' para selecionar uma partição.")
            return
            
        print(f"\nConteúdo de: {self._get_full_path()}")
        print("=" * 50)
        
        # Lista diretórios primeiro
        dirs_found = False
        for entry in self.current_dir.children:
            if entry.is_directory:
                dirs_found = True
                status = "[D]" if entry.is_deleted else ""
                print(f"[DIR] {entry.name}/ {status}")
        
        # Lista arquivos
        files_found = False
        for entry in self.current_dir.children:
            if not entry.is_directory:
                files_found = True
                status = "[D]" if entry.is_deleted else ""
                size_mb = entry.size / (1024*1024) if entry.size > 0 else 0
                print(f"{entry.name} {status} ({size_mb:.2f} MB)")
        
        if not dirs_found and not files_found:
            print("Diretório vazio")
    
    def change_directory(self, args):
        """Muda o diretório atual"""
        if not args:
            print("Uso: cd <diretório>")
            return
        
        path = args[0]
        if path == "..":
            if self.current_dir.parent:
                self.current_dir = self.current_dir.parent
            return
        
        for entry in self.current_dir.children:
            if entry.is_directory and entry.name == path:
                self.current_dir = entry
                return
        
        print(f"Diretório não encontrado: {path}")
    
    def _get_full_path(self):
        """Retorna o caminho completo do diretório atual"""
        path = []
        current = self.current_dir
        while current:
            path.append(current.name)
            current = current.parent
        return "/" + "/".join(reversed(path[:-1]))  # Remove root do caminho
    
    def print_working_directory(self, args=None):
        """Mostra o diretório atual"""
        print(f"Diretório atual: {self._get_full_path()}")
    
    def show_tree(self, args=None):
        """Mostra a estrutura em árvore"""
        self.disk_reader.file_system.display_structure()
    
    def show_help(self, args=None):
        """Mostra a ajuda dos comandos disponíveis"""
        print("\nComandos disponíveis:")
        print("=" * 50)
        print("dir ou ls    - Lista o conteúdo do diretório atual")
        print("cd <dir>     - Muda para o diretório especificado")
        print("cd ..        - Volta para o diretório anterior")
        print("pwd          - Mostra o diretório atual")
        print("tree         - Mostra a estrutura completa em árvore")
        print("back         - Volta para a seleção de partições")
        print("help         - Mostra esta ajuda")
        print("exit         - Sai do programa")
        print("info         - Mostra informações sobre a partição atual")
    
    def exit_program(self, args=None):
        """Sai do programa"""
        print("\nSaindo do programa...")
        sys.exit(0)
    
    def process_command(self, command_line):
        """Processa um comando do usuário"""
        parts = command_line.strip().split()
        if not parts:
            return
        
        command = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else None
        
        if command in self.commands:
            self.commands[command](args)
        else:
            print(f"Comando não reconhecido: {command}")
            print("Digite 'help' para ver os comandos disponíveis")

def main():
    print("MicroRecover - Sistema de Recuperação de Arquivos")
    print("=" * 50)
    
    # Inicializa o leitor de disco
    reader = DiskReader()
    
    # Lista os discos físicos disponíveis
    drives = reader.list_physical_drives()
    if not drives:
        print("Nenhum disco físico encontrado!")
        return
    
    print("\nDiscos disponíveis:")
    for i, drive in enumerate(drives):
        print(f"{i}. {drive}")
    
    # Seleciona o disco
    while True:
        try:
            choice = int(input("\nSelecione o número do disco (0-{}): ".format(len(drives)-1)))
            if 0 <= choice < len(drives):
                break
            print("Escolha inválida!")
        except ValueError:
            print("Por favor, digite um número válido!")
    
    # Lê o disco selecionado
    print(f"\nLendo disco {drives[choice]}...")
    if not reader.read_disk(choice):
        print("Erro ao ler o disco!")
        return
    
    # Inicializa a interface do usuário
    ui = UserInterface()
    
    # Inicia o loop principal da interface
    while True:
        try:
            # Seleciona a partição
            if not ui.select_and_read_partition():
                print("Erro ao ler a partição!")
                break
            
            # Loop de comandos
            while True:
                try:
                    command = input("\n> ")
                    if command.lower() == "back":
                        break
                    ui.process_command(command)
                except KeyboardInterrupt:
                    print("\nVoltando para seleção de partições...")
                    break
                except Exception as e:
                    print(f"Erro: {str(e)}")
            
        except KeyboardInterrupt:
            print("\nSaindo do programa...")
            break
        except Exception as e:
            print(f"Erro: {str(e)}")
            break

if __name__ == "__main__":
    main() 