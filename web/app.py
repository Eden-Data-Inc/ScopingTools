from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    modules = framework.modules
    return render_template('index.html', modules=modules)

@app.route('/run', methods=['POST'])
def run():
    target = request.form['target']
    selected_modules = request.form.getlist('modules')
    results = []

    for module_name in selected_modules:
        results.extend(framework.run_module(module_name, ['-t', target]))

    return render_template('results.html', results=results)

if __name__ == "__main__":
    app.run(debug=True)