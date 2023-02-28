from flask import Flask, jsonify, request
from models import Task, Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
engine = create_engine('sqlite:///db.sqlite3')
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)

@app.route('/tasks', methods=['GET'])
def get_tasks():
    session = Session()
    tasks = session.query(Task).all()
    return jsonify(tasks)

@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    session = Session()
    task = session.query(Task).filter_by(id=task_id).first()
    return jsonify(task)

@app.route('/tasks', methods=['POST'])
def create_task():
    session = Session()
    task = Task(title=request.json['title'], description=request.json['description'], completed=False)
    session.add(task)
    session.commit()
    return jsonify(task)

@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    session = Session()
    task = session.query(Task).filter_by(id=task_id).first()
    task.title = request.json.get('title', task.title)
    task.description = request.json.get('description', task.description)
    task.completed = request.json.get('completed', task.completed)
    session.commit()
    return jsonify(task)

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    session = Session()
    task = session.query(Task).filter_by(id=task_id).first()
    session.delete(task)
    session.commit()
    return jsonify({'result': True})

if __name__ == '__main__':
    app.run(debug=True)
