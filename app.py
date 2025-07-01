from flask import Flask, request, render_template, redirect, url_for, session, flash
import boto3
import uuid
import os

# Flask setup
app = Flask(__name__)
app.secret_key = "b7127b5f7f99f682c84375c6e5cf4fa80734d4d790372f4ae3926a6b6f8c3c6f"

# AWS setup
REGION = 'us-east-1'
dynamodb = boto3.resource('dynamodb', region_name=REGION)
users_table = dynamodb.Table('userdata')
bookings_table = dynamodb.Table('Bookingdata')

sns = boto3.client('sns', region_name=REGION)
sns_topic_arn = 'arn:aws:sns:us-east-1:195275652542:BookingRequestNotifications'

# Send email via AWS SNS
def send_booking_email(email, movie, date, time, seat, booking_id):
    message = f"""
    🎟️ Booking Confirmed!

    Movie: {movie}
    Date: {date}
    Time: {time}
    Seat(s): {seat}
    Booking ID: {booking_id}

    Thank you for booking with us!
    """
    try:
        sns.publish(
            TopicArn=sns_topic_arn,
            Message=message,
            Subject="Your Movie Ticket Booking Confirmation"
        )
        return True
    except Exception as e:
        print(f"Error sending email via SNS: {e}")
        return False

# Routes
@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        password = request.form.get('setPwd')
        confirm_password = request.form.get('confirmPwd')

        if not all([fname, lname, email, password, confirm_password]):
            return "All fields are required.", 400

        if password != confirm_password:
            return "Passwords do not match.", 400

        try:
            existing = users_table.get_item(Key={"email": email}).get("Item")
            if existing:
                return "User already registered.", 400
        except Exception as e:
            print("Error checking user:", e)
            return "Database error", 500

        try:
            users_table.put_item(Item={
                "first_name": fname,
                "last_name": lname,
                "email": email,
                "password": password
            })
            return redirect(url_for('index'))
        except Exception as e:
            print("Error inserting user:", e)
            return "Registration failed", 500

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            user = users_table.get_item(Key={"email": email}).get("Item")
            if user and user['password'] == password:
                session['user'] = email
                return redirect(url_for('main'))
        except Exception as e:
            print("Login error:", e)

        flash("Invalid credentials")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/main')
def main():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('main.html')

@app.route('/booking')
def booking_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    movie = request.args.get('movie')
    
    booked = bookings_table.scan(
        FilterExpression=boto3.dynamodb.conditions.Attr("Movie").eq(movie)
    ).get("Items", [])
    
    booked_seats = []
    for b in booked:
        if "Seat" in b:
            seats = b["Seat"].split(", ")
            booked_seats.extend(seats)

    return render_template('booking.html', movie=movie, booked_seats=booked_seats)

@app.route('/book', methods=['POST'])
def book_ticket():
    if 'user' not in session:
        return redirect(url_for('login'))

    data = {
        'email': session['user'],  # ✅ FIXED
        'Movie': request.form['movie'],
        'Date': request.form['date'],
        'Time': request.form['time'],
        'Seat': request.form['seat'],
        'BookingID': str(uuid.uuid4())
    }

    try:
        bookings_table.put_item(Item=data)

        # ✅ Send SNS email notification
        send_booking_email(
            data['email'], data['Movie'], data['Date'], data['Time'], data['Seat'], data['BookingID']
        )

        return render_template('tickets.html', booking=data)
    except Exception as e:
        print("Booking error:", e)
        flash("Booking failed. Please try again.")
        return redirect(url_for('main'))

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
