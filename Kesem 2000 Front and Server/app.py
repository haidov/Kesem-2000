import datetime
import itertools
import json
import io
import os
import sqlite3 as lite
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (Flask, flash, jsonify, logging, redirect, render_template,
                   request, session, url_for)
from passlib.hash import sha256_crypt
from sqlalchemy.orm import query
from wtforms import (Form, IntegerField, PasswordField, SelectField,
                     StringField, TextAreaField, validators)

from urllib.parse import unquote

# Init app
app = Flask(__name__) 
basedir = os.path.abspath(os.path.dirname(__file__))

# Init connection to users database - not sure if needed
'''
try:
    conn = lite.connect('users.db')
    curs = conn.cursor()
    print ("Opened users database successfully")
except:
    print ("shit")
'''

def Log(action_to_log):
    with open('log.txt', 'a', encoding="utf-8") as outfile:  
        now = datetime.now()
        t = datetime.strptime(str(now), '%Y-%m-%d %H:%M:%S.%f')
        t = t.strftime("%d-%m-%Y %H:%M")
        outfile.write(str(t) + " " + session['username'] + " - " + action_to_log + "\n")


def Connect_Execute(database_name, query):
    try:
        conn = lite.connect(database_name + '.db')
        curs = conn.cursor()
        curs.execute(query)
        return curs.fetchall()
    except:
        flash("Failed to open " + database_name, "danger")


def TheCollector(db_name, query):
    try:
        fixed_titles = []
        array_of_info = []
        conn = lite.connect(db_name)
        curs = conn.cursor()
        curs.execute(query)
        db_data = curs.fetchall()
        names = [description[0] for description in curs.description]
        
        for name in names:
            t = name.replace("_", " ")
            t = t.replace("onn", "on")
            t = t.title()
            fixed_titles.append(t)   
        
        for d in db_data:
            array_of_info.append(dict(zip(fixed_titles, d)))
    except:
        flash("Failed to open " + db_name, "danger")

    return array_of_info


def Get_Recent_Data():
    # First, get all customers

    array_of_info = []
    fixed_array_of_info = []
    all_names = []
    all_fixed_names = []

    conn = lite.connect('customers.db')
    curs = conn.cursor()
    curs.execute('SELECT * FROM customers')
    all_customers_info = curs.fetchall()    

    titles = [description[0] for description in curs.description]

    for d in all_customers_info:
        array_of_info.append(dict(zip(titles, d)))

    # Get recent data of each db and append it to the customers info
    for name in all_customers_info:
        all_names.append(name[1])

    for name in all_names:
        fixed_name = name
        fixed_name = fixed_name.lower()
        fixed_name = fixed_name.replace(" ", "_")
        fixed_name = fixed_name + "_table.db"
        all_fixed_names.append(fixed_name)

    i = -1
    for name in all_fixed_names:

        i = i + 1
        provider = array_of_info[i]["provider"]
        limit = array_of_info[i]["number_of_devices"]
        q = '''
SELECT * from (SELECT *, MAX (timestamp) AS 'last_update' FROM devices
GROUP BY name) AS 'step_1'
ORDER BY 'last_update' DESC
LIMIT ''' + str(limit)

        add_me_to_info = TheCollector(name, q)
        a = [array_of_info[i]]
        a.append(add_me_to_info)
        fixed_array_of_info.append(a)

    return fixed_array_of_info


# gets all the alarms from the devices table
def getAllAlarms(db_name):
    db_conn = lite.connect(db_name)
    c = db_conn.cursor()
    c.execute('''
                select Name,Alarm,Timestamp from devices order by Name,Timestamp
              '''
              )
    data = []
    currentRow = c.fetchone()
    while currentRow != None:
        data.append(currentRow)
        currentRow = c.fetchone()
    return data

# this function finds the range of a given state(in error, no errors, other error types)
def findStateRange(data, index):
    deviceName = data[index][0]
    initial_state = data[index][1]
    initial_timestamp = data[index][2]
    while index < (len(data) - 1) and data[index][1] == initial_state and deviceName == data[index][0]:
        index += 1
    final_timestamp = data[index - 1][2]
    if index == (len(data) - 1):
        final_timestamp = data[index][2]
    lastIndex = index
    return deviceName, initial_state, "%s - %s" % (initial_timestamp, final_timestamp), lastIndex

# this function iterates all over the data and puts all the different time ranges of alarms in a nice dictionary
def findAllRangeStates(data):
    index = 0
    alarms_array = []
    while index < (len(data) - 1):
        deviceName, initial_state, time_range, index = findStateRange(data, index)
        if initial_state != "0" and deviceName not in alarms_array:

            alarms_array.append([deviceName, initial_state, time_range])
            
    return alarms_array
    
def Get_All_Alarms():
    # First, get all customers

    array_of_info = []
    fixed_array_of_info = {}
    all_names = []
    all_fixed_names = []

    all_alarms = []

    all_customers_info = Connect_Execute('customers', 'SELECT * FROM customers')

    # Get recent data of each db and append it to the customers info
    for name in all_customers_info:
        all_names.append(name[1])

    for name in all_names:
        fixed_name = name
        fixed_name = fixed_name.lower()
        fixed_name = fixed_name.replace(" ", "_")
        fixed_name = fixed_name + "_table.db"
        all_fixed_names.append(fixed_name)

    i = -1
    for name in all_fixed_names:
        try:
            i = i + 1
            data = getAllAlarms(name)
            time_ranges = findAllRangeStates(data)
            if time_ranges:
                all_alarms.append({all_names[i]: time_ranges})
        except:
            pass
        
    return all_alarms


def Get_Active_Alarms():
    # First, get all customers

    array_of_info = []
    fixed_array_of_info = {}
    all_names = []
    all_fixed_names = []
    active_alarms = []

    conn = lite.connect('customers.db')
    curs = conn.cursor()
    curs.execute('SELECT * FROM customers')
    all_customers_info = curs.fetchall()    

    titles = [description[0] for description in curs.description]

    for d in all_customers_info:
        array_of_info.append(dict(zip(titles, d)))

    # Get recent data of each db and append it to the customers info
    for name in all_customers_info:
        all_names.append(name[1])

    for name in all_names:
        fixed_name = name
        fixed_name = fixed_name.lower()
        fixed_name = fixed_name.replace(" ", "_")
        fixed_name = fixed_name + "_table.db"
        all_fixed_names.append(fixed_name)

    i = -1
    for name in all_fixed_names:

        i = i + 1
        provider = array_of_info[i]["provider"]
        limit = array_of_info[i]["number_of_devices"]

        q = '''
SELECT * from (SELECT timestamp, name, alarm, MAX (timestamp) AS 'last_update' FROM devices WHERE alarm IS NOT 0
GROUP BY name) AS 'step_1'
ORDER BY 'last_update' DESC
LIMIT ''' + str(limit)            
        
        add_me_to_info = TheCollector(name, q)
        fixed_array_of_info[name] = add_me_to_info

        # We got all recent alarms - but are they still active?

        for alarm in fixed_array_of_info[name]:
            q = "SELECT timestamp, name, alarm, MAX (timestamp) AS 'last_update' FROM devices WHERE name IS \"" + alarm['Name'] + "\""

            last = TheCollector(name, q)

            if alarm["Alarm"] != last[0]["Alarm"]:
                print(alarm["Alarm"] + " is not equel to " + last[0]["Alarm"])
                fixed_array_of_info[name].remove(alarm)
    return fixed_array_of_info


def Get_All_Data():
    # First, get all customers

    array_of_info = []
    fixed_array_of_info = {}
    all_names = []
    all_fixed_names = []

    all_customers_info = Connect_Execute('customers', 'SELECT * FROM customers')

    # Get all data of each db and append it to the customers info
    for name in all_customers_info:
        all_names.append(name[1])

    for name in all_names:
        fixed_name = name
        fixed_name = fixed_name.lower()
        fixed_name = fixed_name.replace(" ", "_")
        fixed_name = fixed_name + "_table.db"
        all_fixed_names.append(fixed_name)

    i = -1
    for name in all_names:
        i = i + 1

        add_me_to_info = TheCollector(all_fixed_names[i], '''
        SELECT * FROM devices ''')

        fixed_array_of_info[name] = add_me_to_info

    return fixed_array_of_info


# Check if user logged in

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# Register Form Class

class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
    Log("Entered Registering Page.")
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        conn = lite.connect('users.db')
        curs = conn.cursor()
        curs.execute('INSERT INTO users (name, username, email, password) VALUES (?, ?, ?, ?)', (name, username, email, password))
        print("name: " + name + " username: " + username + " email: " + email + " password: " + password)
        conn.commit()
        flash('You are now registered and can log in', 'success')

        return redirect(url_for('index'))
    return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Get user by username
        conn = lite.connect('users.db')
        curs = conn.cursor()
        curs.execute('SELECT * FROM users WHERE username = ?', [username])
        rows = curs.fetchall()
        if len(rows) == 0:
            error = "Username not found"
            return render_template('login.html', error=error)
        for row in rows:
            # Get stored hash
            password = row[2]
            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect('/')
            else:
                error = "Invalid Login"
                return render_template('login.html', error=error)
    return render_template('login.html')

# Dashboard
@app.route('/')
@is_logged_in
def index():
    Log("Entered Dashboard.")

    customers = Connect_Execute("customers", 'SELECT * FROM customers')

    customers_data = Get_Recent_Data()

    with open("dashboard info.txt", 'w', encoding="utf-8") as f:  
        f.write(str(customers_data))

    if len(customers) == 0:
        msg = 'No Customers Found'
        return render_template('home.html', msg=msg)
    
    return render_template('home.html', customers=customers, all_data = customers_data)

# Logout
@app.route('/logout')
def logout():
    Log("Entered Logout.")
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Add Customer Class
class CustomerForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    ip = StringField('IP', [validators.Length(min=1, max=50)])
    port = IntegerField('Port', [validators.NumberRange(min=1)])
    username = StringField('User Name', [validators.Length(min=1, max=25)])
    password = StringField('Password', [validators.Length(min=1, max=25)])
    provider = SelectField(label='Provider', 
        choices=[('Cool Expert', 'Cool Expert'), ('Danfoss', "Danfoss"), ('Dixell', 'Dixell'), ('RDM', "RDM")])
    phone = StringField('Phone', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=1, max=50)])
    address = StringField('Address', [validators.Length(min=1, max=50)])
    contact_name = StringField('Contact Name', [validators.Length(min=1, max=50)])

@app.route('/<path:page>', methods=['GET' ,'POST'])
def show(page):
    if request.method == 'POST':
        print("nice")
    return render_template('includes/_navbar.html')


@app.route('/add_customer', methods=['GET' ,'POST'])
@is_logged_in
def add_customer():
    Log("Entered Add Customer Page.")
    form = CustomerForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        ip = form.ip.data
        port = form.port.data
        username = form.username.data
        password = form.password.data
        provider = form.provider.data
        phone = form.phone.data
        email = form.email.data
        address = form.address.data
        contact_name = form.address.data

        # Enter to the database
        conn = lite.connect('customers.db')
        curs = conn.cursor()
        print ("customers.db was opened successfully")
        curs.execute('INSERT INTO customers (name, ip, port, username, password, provider, phone, email, address, contact_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (name, ip, port, username, password, provider, phone, email, address, contact_name))
        conn.commit()
        curs.close()
        
        tempate_name = provider.replace(" ", "_").lower() + "_template.txt"
        crawler_name = name.replace(" ", "_").lower() + "_crawler.py"
        customer_name = name.replace(" ", "_").lower()

        with open(tempate_name, 'r') as file:  
            data = file.read()
            
            data = data.replace("{put}", name).replace("{customer_name}", customer_name).replace("{ip}", ip).replace("{port}", str(port)).replace("{username}", username).replace("{password}", password)

            print(data)
        with open(crawler_name, 'w') as f:  
            f.write(data)

        flash("Customer Created", "success")
        return redirect(url_for("add_customer"))
    return render_template('add_customer.html', form=form)

@app.route('/customer/<string:ip>/')
def customer(ip):
    Log("Entered Customers Page.")

    conn = lite.connect('customers.db')
    curs = conn.cursor()
    curs.execute('SELECT * FROM customers WHERE ip = ?', [ip])

    customer = curs.fetchone()
    print(customer)
    return render_template('customer.html', customer=customer)


@app.route('/<string:customer_name>/device/<string:device_name>/')
def device(customer_name, device_name):
    Log("Entered Device Page of " + str(customer_name) + " with device id of " + str(device_name) + ".")
    fixed_titles = []
    fixed_all_timestamps = []
    fixed_column_names = []
    cn = customer_name
    customer_name = customer_name.lower()
    customer_name = customer_name.replace(" ", "_")
    customer_name = customer_name + "_table"
    q = 'SELECT * FROM devices WHERE name = \"' + str(device_name) + "\""
    last_data = Connect_Execute(customer_name, q)

    all_data = last_data
    print("last data:")
    last_data = last_data[-1]

    # Find the provider

    q = 'SELECT * FROM customers WHERE name = \"' + str(cn) + "\""
    provider = Connect_Execute("customers", q)

    print(customer_name)

    q = 'SELECT timestamp FROM devices WHERE name = \"' + str(device_name) + "\""

    all_timestamps = Connect_Execute(customer_name, q)

    for timestamp in all_timestamps:
        timestamp = str(timestamp).replace(",", "")
        timestamp = timestamp.replace('\'', "")
        timestamp = timestamp.replace('(', "")
        timestamp = timestamp.replace(')', "")
        t = datetime.strptime(str(timestamp), '%d-%m-%Y %H:%M')
    #    print("Timestamp is " + str(t))
        now = datetime.now()
    #    print ("Now is " + str(now))
    #    print ("Now - timedelta is " + str(now-timedelta(minutes=60)))
        if now-timedelta(minutes=60) <= t <= now:
            fixed_all_timestamps.append(timestamp)
        #    print("FUCK YES")
            print(timestamp)

    q = 'PRAGMA table_info(devices)'
    titles = Connect_Execute(customer_name, q)
    for title in titles:
        t = title[1]
        t = t.replace("_", " ")
        t = t.replace("onn", "on")
        t = t.title()
        fixed_titles.append(t)

    fixed_all_data = []
    for d in all_data:
        fixed_all_data.append(dict(zip(fixed_titles, d)))

    with open('last_data.txt', 'w') as outfile:  
        json.dump(fixed_all_data, outfile)

    return render_template('device.html', device=last_data, provider=provider, titles=fixed_titles, all_timestamps=json.dumps(fixed_all_timestamps), all_data=json.dumps(fixed_all_data))

# Diagram Page
@app.route('/<string:customer_name>/diagram/', methods=['GET' ,'POST'])
def diagram(customer_name):
    Log("Entered customer " + str(customer_name) + " Diagram")
    
    cn = customer_name
    customer_name = customer_name.lower().replace(" ", "_")
    
    jsonDiagramFileName = customer_name + '.json'
    # Save the json if post request.
    if request.method == 'POST':
        jsonDiagram = request.form.get('jsonDiagram')
        print(jsonDiagram)
        with io.open(jsonDiagramFileName, 'w', encoding='utf8') as jsonDiagramFile:
            jsonDiagramFile.write(jsonDiagram)
    
    
    # Get temperature by provider.

    q =  'SELECT * FROM customers WHERE name = \"' + str(cn) + "\""
    provider = Connect_Execute("customers", q)[0][6]
    tempKey = [[['Control Temp R','Probe 1 R'][provider == 'Dixell'],'_u17_ther_air_CID_0_VID_2532_R'][provider == 'Danfoss'], 'Nvoairtemp'][provider == 'Cool Expert']
    
    # Get name, alarm and temperature from the database.
    q =  "SELECT name, alarm, " + tempKey.replace(" ", "_") + " FROM devices"
    names_alarms_and_temps = Connect_Execute(customer_name + "_table", q)
    
    NAME = 0
    ALARM = 1
    TEMP = 2
    alarms_temps_by_names_dict = {}
    for name_alarm_and_temp in names_alarms_and_temps:   
        alarms_temps_by_names_dict[name_alarm_and_temp[NAME]] = [name_alarm_and_temp[ALARM], str(name_alarm_and_temp[TEMP])]

    # Get the json from the file for the client.
    jsonDiagram = ""
    if os.path.isfile(jsonDiagramFileName):   
        with io.open(jsonDiagramFileName, 'r', encoding='utf8') as jsonDiagramFile:  
            jsonDiagram = jsonDiagramFile.read()

    return render_template('diagram.html', jsonDiagram=jsonDiagram, alarms_temps_by_names_dict=alarms_temps_by_names_dict)




# Charts
@app.route('/charts', methods=['GET', 'POST'])
@is_logged_in
def charts():
    literaly_all_data = Get_All_Data()

    with open('data_2.txt', 'w') as outfile:  
        json.dump(literaly_all_data, outfile)

    # Create Json with all the info
    # Like this: {
    # "provider_name": [
    #    {
    #       "device_name": {
    #            "value": "YouTube Developers Live: Embedded Web Player Customization"
    #        }
    #    }
    #   ],
    #   "provider_name":
    #}

    if request.method == 'POST':
        all_info = []
        result = request.form
        for item in result.items():
            all_info.append(item)

        customer = all_info[0][1]
        device = all_info[1][1]
        attribute = all_info[2][1]

        customer = customer.lower()
        customer = customer.replace(" ", "_")
        customer = customer.replace("-", "_")

        attribute = attribute.lower()
        attribute = attribute.replace(" ", "_")
        attribute = attribute.replace("-", "_")

        conn = lite.connect(customer + "_table.db")
        curs = conn.cursor()
        query = 'SELECT DISTINCT timestamp, name, ' + str(attribute) + ' FROM devices WHERE name = ' + '"' + str(device) + '"'
        curs.execute(query)
        print(query)
        info_for_chart = curs.fetchall()
        print(info_for_chart)
        # Here I need to send info_for_chart to the front end

        return jsonify({'info_for_chart' : info_for_chart})

    customers = Connect_Execute('customers', 'SELECT * FROM customers')
    if len(customers) == 0:
        msg = 'No Customers Found'
        return render_template('home.html', msg=msg)
    return render_template('charts.html', customers=customers, all_data=json.dumps(literaly_all_data))


@app.route('/alarms', methods=['GET', 'POST'])
@is_logged_in
def alarms():
    Log("Entered Alarms Page.")

    alarms = Get_All_Alarms()
    customers = Connect_Execute("customers", 'SELECT * FROM customers')

    # But what are the active alarms?
    active_alarms = Get_Active_Alarms()

    for k, v in dict(active_alarms).items():
        if len(v) == 0:
            del active_alarms[k]

    print("Active Alarms: \n" + str(active_alarms))
    print("All Alarms: \n" + str(alarms))

    for table in active_alarms:
        fix_table = table
        fix_table = fix_table.replace("table.db", "")
        fix_table = fix_table.replace("_", " ")
        fix_table = fix_table.title()
        if fix_table[-1] == " ":
            fix_table = fix_table[:-1]
        fix_table = fix_table.replace("Rdm", "RDM")
        for table2 in alarms:
            for v in table2:
                for timestamp in active_alarms[table]:
                    if fix_table in table2:
                        for alarm in table2[fix_table]:
                            if timestamp["Timestamp"] in str(alarm[2].split(" - ")[1]) and "red" not in alarm:
                                print (alarm[2].split(" - ")[1], timestamp["Timestamp"])
                                alarm.append("red")
                            

    print("All Alarms: \n" + str(alarms))
    if len(customers) == 0:
        msg = 'No Customers Found'
        return render_template('home.html', msg=msg)
    return render_template('alarms.html', alarms=alarms)

'''
@app.route('/add_customer', methods=['POST'])
@is_logged_in
def add_customer():
    Log("Entered Add Customer Page")


    messeges = []
    errors = False
    result = request.form
    print(result)
    if result["customer_name_input"] == "":
        flash ('Customer name missing', 'danger')
        errors = True
    if result["ip_input"] == "":
        flash ('I.P missing', 'danger')
        errors = True
    if result["username_input"] == "":
        flash ('User Name missing', 'danger')
        errors = True
    if result["password_input"] == "":
        flash ('Password missing', 'danger')
        errors = True
    if result["port_input"] == "":
        flash ('Port missing', 'danger')
        errors = True
    if result["provider"] == "":
        flash ('Provider missing', 'danger')
        errors = True
    if errors == False:
        tempate_name = result["provider"].replace(" ", "_").lower() + "_template.txt"
        crawler_name = result["customer_name_input"].replace(" ", "_").lower() + "_crawler.py"
        customer_name = result["customer_name_input"].replace(" ", "_").lower()

        with open(tempate_name, 'r') as file:  
            data = file.read()
            
            data = data.replace("{customer_name}", customer_name).replace("{ip}", result["ip_input"]).replace("{port}", result["port_input"]).replace("{username}", result["username_input"]).replace("{password}", result["password_input"])

            print(data)
        with open(crawler_name, 'w') as f:
            f.write(data)

        flash('Customer added successfully', 'success')
    return redirect('/')
'''

@app.route('/get_alarms', methods=['POST'])
@is_logged_in
def get_alarms():
    # First, get all customers and their respective provider

    customers = Connect_Execute("customers", 'SELECT * FROM customers')

    session_alarms = Get_Active_Alarms()

    # session_alarms = {"פילסברי" : danfoss_alarms, "Swissport" : dixell_alarms, "אושר עד (RDM)" : rdm_alarms}

    # for key in list(session_alarms):
    #    if bool(session_alarms[key]) == False:
    #        session_alarms.pop(key, None)
    
    # print(session_alarms)
    return jsonify(session_alarms)

@app.route('/edit_customer', methods=['GET' ,'POST'])
@is_logged_in
def edit_customer():
    customers = Connect_Execute('customers', 'SELECT * FROM customers')
    Log("Entered Edit Customer Page.")
    form = CustomerForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        ip = form.ip.data
        port = form.port.data
        username = form.username.data
        password = form.password.data
        provider = form.provider.data
        phone = form.phone.data
        email = form.email.data
        address = form.address.data
        contact_name = form.address.data

        # Enter to the database
        conn = lite.connect('customers.db')
        curs = conn.cursor()
        print("customers.db was opened successfully")
        q = '''UPDATE customers SET name = \'''' + str(name) + '''\', ip = \'''' + str(ip) + '''\', port = \'''' + str(port) + '''\', username = \'''' + str(username) + '''\', password = \'''' + str(password) + '''\', provider = \'''' + str(provider) + '''\', phone = \'''' + str(phone) + '''\', email = \'''' + str(email) + '''\', address = \'''' + str(address) + '''\', contact_name = \'''' + str(contact_name) + '''\' WHERE id = 1 '''
        curs.execute(q)
        conn.commit()
        curs.close()

        flash('Customer ' + str(name) + ' edited successfully', 'success')
        return redirect(url_for("edit_customer"))

    return render_template('edit_customer.html', form=form, customers=customers)

@app.route('/edit_customer_chosen', methods=['GET', 'POST'])
@is_logged_in
def edit_customer_chosen():
    if request.method == 'POST':
        all_info = []
        print("nice")
        result = request.form
        for item in result.items():
            all_info.append(item)

        q = 'SELECT * FROM customers WHERE name = \"' + str(all_info[0][1]) + "\""
        chosen_customer = Connect_Execute("customers", q)
        print(chosen_customer)
        return jsonify({'info_for_edit': chosen_customer})

if __name__ == '__main__':
    app.secret_key = "secret123"
    app.run(debug=True)
