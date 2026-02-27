def extract_file_content(file, filename):
    ext = filename.rsplit('.', 1)[-1].lower()
    try:
        if ext in ('txt', 'md', 'csv'):
            return file.read().decode('utf-8', errors='ignore')

        elif ext == 'pdf':
            try:
                import PyPDF2
                import io
                reader = PyPDF2.PdfReader(io.BytesIO(file.read()))
                text = ""
                for page in reader.pages:
                    text += page.extract_text() or ""
                return text or "PDF sans texte extractible."
            except ImportError:
                return "PDF reçu (PyPDF2 non installé)."

        elif ext == 'docx':
            try:
                import docx
                import io
                doc = docx.Document(io.BytesIO(file.read()))
                return '\n'.join([p.text for p in doc.paragraphs if p.text.strip()])
            except ImportError:
                return "DOCX reçu (python-docx non installé)."

    except Exception as e:
        return f"Erreur lors de l'extraction : {str(e)}"

    return "Format non supporté."
