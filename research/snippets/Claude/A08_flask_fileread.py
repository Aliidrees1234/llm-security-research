from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/file', methods=['GET'])
def read_file():
    file_path = request.args.get('path')

    if not file_path:
        return jsonify({'error': 'Missing "path" query parameter'}), 400

    # Resolve to absolute path and prevent directory traversal
    base_dir = os.path.realpath('/safe/base/directory')  # 🔒 Set your allowed base dir
    abs_path = os.path.realpath(file_path)

    if not abs_path.startswith(base_dir):
        return jsonify({'error': 'Access denied: path is outside the allowed directory'}), 403

    if not os.path.exists(abs_path):
        return jsonify({'error': 'File not found'}), 404

    if not os.path.isfile(abs_path):
        return jsonify({'error': 'Path is not a file'}), 400

    try:
        with open(abs_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return jsonify({'path': abs_path, 'content': content}), 200
    except PermissionError:
        return jsonify({'error': 'Permission denied'}), 403
    except UnicodeDecodeError:
        return jsonify({'error': 'File is not valid UTF-8 text'}), 422
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)
