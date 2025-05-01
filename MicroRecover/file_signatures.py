class FileSignature:
    def __init__(self, signature, extension, description):
        self.signature = signature
        self.extension = extension
        self.description = description

# Lista de assinaturas de arquivos comuns
FILE_SIGNATURES = [
    # Imagens
    FileSignature(b'\xFF\xD8\xFF', '.jpg', 'JPEG Image'),
    FileSignature(b'\x89PNG\r\n\x1a\n', '.png', 'PNG Image'),
    FileSignature(b'GIF87a', '.gif', 'GIF Image'),
    FileSignature(b'GIF89a', '.gif', 'GIF Image'),
    
    # Documentos
    FileSignature(b'%PDF-', '.pdf', 'PDF Document'),
    FileSignature(b'PK\x03\x04', '.zip', 'ZIP Archive'),
    FileSignature(b'PK\x05\x06', '.zip', 'ZIP Archive'),
    
    # Áudio/Video
    FileSignature(b'ID3', '.mp3', 'MP3 Audio'),
    FileSignature(b'OggS', '.ogg', 'Ogg Audio'),
    FileSignature(b'RIFF', '.wav', 'WAV Audio'),
    
    # Outros
    FileSignature(b'<?xml', '.xml', 'XML Document'),
    FileSignature(b'<!DOCTYPE HTML', '.html', 'HTML Document'),
]

def find_file_signature(data):
    """
    Procura por assinaturas de arquivos conhecidas nos dados fornecidos.
    Retorna uma lista de tuplas (offset, signature) para cada assinatura encontrada.
    """
    found_signatures = []
    
    for signature in FILE_SIGNATURES:
        pos = 0
        while True:
            pos = data.find(signature.signature, pos)
            if pos == -1:
                break
            found_signatures.append((pos, signature))
            pos += 1
    
    return found_signatures

def get_file_extension(signature):
    """Retorna a extensão do arquivo baseado na assinatura"""
    for sig in FILE_SIGNATURES:
        if sig.signature == signature:
            return sig.extension
    return '.bin'  # Extensão padrão se não encontrar correspondência 