from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from mistralai import Mistral
from database import db, User, Message, UserFile, UserMemory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, json, base64
from file_processor import extract_file_content

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'jackson_storm_dev_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///jackson.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max

db.init_app(app)

MISTRAL_API_KEY = os.environ.get('MISTRAL_API_KEY',"tEhszaQ26HXgu65TJL89KSZC38xVl0i2")
client = Mistral(api_key=MISTRAL_API_KEY)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'Admin')

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx', 'md', 'csv'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_user():
    if 'user_id' not in session:
        return None
    return User.query.get(session['user_id'])


# ══════════════════════════════════════════════════════════════
#  INIT DB
# ══════════════════════════════════════════════════════════════

with app.app_context():
    db.create_all()


# ══════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return jsonify({'ok': True, 'user': user.to_dict()})
        return jsonify({'ok': False, 'error': 'Identifiants incorrects'}), 401
    return render_template('auth.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')
    avatar_emoji = data.get('avatar_emoji', '👤')

    if not username or len(username) < 2:
        return jsonify({'ok': False, 'error': 'Nom trop court'}), 400
    if not password or len(password) < 4:
        return jsonify({'ok': False, 'error': 'Mot de passe trop court (4 caractères min)'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'ok': False, 'error': 'Ce nom est déjà pris'}), 400

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        avatar_emoji=avatar_emoji,
        avatar_type='emoji'
    )
    db.session.add(user)
    db.session.commit()
    session['user_id'] = user.id
    return jsonify({'ok': True, 'user': user.to_dict()})


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/profile', methods=['POST'])
def update_profile():
    user = get_current_user()
    if not user:
        return jsonify({'ok': False}), 401
    data = request.json
    if 'avatar_emoji' in data:
        user.avatar_emoji = data['avatar_emoji']
        user.avatar_type = 'emoji'
    if 'username' in data and data['username'] != user.username:
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'ok': False, 'error': 'Nom déjà pris'}), 400
        user.username = data['username']
    if 'password' in data and data['password']:
        if len(data['password']) < 4:
            return jsonify({'ok': False, 'error': 'Mot de passe trop court'}), 400
        user.password_hash = generate_password_hash(data['password'])
    db.session.commit()
    return jsonify({'ok': True, 'user': user.to_dict()})


@app.route('/profile/avatar', methods=['POST'])
def upload_avatar():
    user = get_current_user()
    if not user:
        return jsonify({'ok': False}), 401
    if 'avatar' not in request.files:
        return jsonify({'ok': False, 'error': 'Pas de fichier'}), 400
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'ok': False}), 400
    data = file.read()
    b64 = base64.b64encode(data).decode('utf-8')
    mime = file.content_type or 'image/png'
    user.avatar_b64 = f"data:{mime};base64,{b64}"
    user.avatar_type = 'image'
    db.session.commit()
    return jsonify({'ok': True, 'user': user.to_dict()})


# ══════════════════════════════════════════════════════════════
#  ROUTES PRINCIPALES
# ══════════════════════════════════════════════════════════════

@app.route('/')
def home():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('chat.html', user=user)


# ══════════════════════════════════════════════════════════════
#  CHAT
# ══════════════════════════════════════════════════════════════

@app.route('/chat', methods=['POST'])
def chat():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non connecté'}), 401

    data = request.json
    user_message = data.get('message', '').strip()
    if not user_message:
        return jsonify({'error': 'Message vide'}), 400

    # Récupérer les fichiers de l'utilisateur
    user_files = UserFile.query.filter_by(user_id=user.id).all()
    files_context = ""
    if user_files:
        files_context = "\n\nFichiers de l'utilisateur :\n"
        for f in user_files:
            files_context += f"\n--- {f.filename} ---\n{f.content_summary}\n"

    # Récupérer la mémoire de l'utilisateur
    memories = UserMemory.query.filter_by(user_id=user.id).order_by(UserMemory.id.desc()).limit(20).all()
    memory_context = ""
    if memories:
        memory_context = "\n\nCe que tu sais sur cet utilisateur :\n"
        for m in memories:
            memory_context += f"- {m.memory_text}\n"

    # Historique récent (10 derniers messages)
    history = Message.query.filter_by(user_id=user.id).order_by(Message.id.desc()).limit(10).all()
    history = list(reversed(history))
    messages_history = [{"role": m.role, "content": m.content} for m in history]

    system_prompt = f"""Tu es un assistant IA intelligent et bienveillant, inspiré de Claude d'Anthropic.
Tu t'adaptes à chaque utilisateur et mémorises ses préférences au fil du temps.
Tu réponds toujours en français sauf si l'utilisateur parle une autre langue.

L'utilisateur s'appelle : {user.username}
{memory_context}
{files_context}

IMPORTANT : À la fin de chaque réponse, si tu détectes une préférence, habitude ou information importante sur l'utilisateur, ajoute une ligne cachée au format :
[MEMORY: description courte de la préférence/info]
Cette ligne ne sera pas affichée à l'utilisateur."""

    messages_history.append({"role": "user", "content": user_message})

    try:
        response = client.chat.complete(
            model="mistral-small-latest",
            messages=[{"role": "system", "content": system_prompt}] + messages_history
        )
        full_response = response.choices[0].message.content

        # Extraire et sauvegarder les mémoires
        response_text = full_response
        if '[MEMORY:' in full_response:
            lines = full_response.split('\n')
            clean_lines = []
            for line in lines:
                if line.strip().startswith('[MEMORY:') and line.strip().endswith(']'):
                    memory_text = line.strip()[8:-1].strip()
                    if memory_text:
                        mem = UserMemory(user_id=user.id, memory_text=memory_text)
                        db.session.add(mem)
                else:
                    clean_lines.append(line)
            response_text = '\n'.join(clean_lines).strip()

        # Sauvegarder les messages
        db.session.add(Message(user_id=user.id, role='user', content=user_message))
        db.session.add(Message(user_id=user.id, role='assistant', content=response_text))
        db.session.commit()

        return jsonify({'response': response_text})

    except Exception as e:
        return jsonify({'response': f"Erreur : {str(e)}"}), 500


# ══════════════════════════════════════════════════════════════
#  FICHIERS
# ══════════════════════════════════════════════════════════════

@app.route('/files', methods=['GET'])
def get_files():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non connecté'}), 401
    files = UserFile.query.filter_by(user_id=user.id).all()
    return jsonify({'files': [f.to_dict() for f in files]})


@app.route('/files/upload', methods=['POST'])
def upload_file():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non connecté'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'Pas de fichier'}), 400
    file = request.files['file']
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Format non supporté (txt, pdf, docx, md, csv)'}), 400

    filename = secure_filename(file.filename)
    content = extract_file_content(file, filename)

    user_file = UserFile(
        user_id=user.id,
        filename=filename,
        content_summary=content[:8000]  # max 8000 chars stockés
    )
    db.session.add(user_file)
    db.session.commit()
    return jsonify({'ok': True, 'file': user_file.to_dict()})


@app.route('/files/<int:file_id>', methods=['DELETE'])
def delete_file(file_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non connecté'}), 401
    f = UserFile.query.filter_by(id=file_id, user_id=user.id).first()
    if not f:
        return jsonify({'error': 'Fichier introuvable'}), 404
    db.session.delete(f)
    db.session.commit()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  HISTORIQUE
# ══════════════════════════════════════════════════════════════

@app.route('/history')
def get_history():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non connecté'}), 401
    messages = Message.query.filter_by(user_id=user.id).order_by(Message.id.asc()).all()
    return jsonify({'messages': [{'role': m.role, 'content': m.content} for m in messages]})


@app.route('/history/clear', methods=['POST'])
def clear_history():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Non connecté'}), 401
    Message.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════
#  ADMIN
# ══════════════════════════════════════════════════════════════

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin'):
        return redirect(url_for('admin_panel'))
    error = None
    if request.method == 'POST':
        if request.form.get('username') == ADMIN_USERNAME and request.form.get('password') == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_panel'))
        error = "Identifiants incorrects."
    return render_template('admin_login.html', error=error)


@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))
    users = User.query.all()
    total_messages = Message.query.count()
    total_files = UserFile.query.count()
    return render_template('admin_panel.html', users=users,
                           total_messages=total_messages, total_files=total_files)


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if not session.get('admin'):
        return jsonify({'error': 'Non autorisé'}), 403
    user = User.query.get_or_404(user_id)
    Message.query.filter_by(user_id=user_id).delete()
    UserFile.query.filter_by(user_id=user_id).delete()
    UserMemory.query.filter_by(user_id=user_id).delete()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/admin/users/<int:user_id>/reset_memory', methods=['POST'])
def admin_reset_memory(user_id):
    if not session.get('admin'):
        return jsonify({'error': 'Non autorisé'}), 403
    UserMemory.query.filter_by(user_id=user_id).delete()
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/admin/users/<int:user_id>/messages')
def admin_user_messages(user_id):
    if not session.get('admin'):
        return jsonify({'error': 'Non autorisé'}), 403
    messages = Message.query.filter_by(user_id=user_id).order_by(Message.id.asc()).all()
    return jsonify({'messages': [{'role': m.role, 'content': m.content} for m in messages]})


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))


if __name__ == '__main__':
    app.run(debug=False, port=5000, host='0.0.0.0')
