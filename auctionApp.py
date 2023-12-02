import random
import string
from flask import Flask, jsonify, render_template, request, session, redirect, url_for, flash
from flask_admin import Admin
from flask_admin.contrib.peewee import ModelView
from peewee import SqliteDatabase, Model, CharField, BlobField, FloatField, IntegerField, DateTimeField, Check
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from postmarker.core import PostmarkClient
from werkzeug.utils import secure_filename
from playhouse.migrate import SqliteMigrator, migrate
from random import randint

from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'memory'

# Image Upload
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Flask-Mail configuration
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USERNAME'] = 'onlineauctionwebapp@gmail.com'
# app.config['MAIL_PASSWORD'] = 'onlineTORONTO'
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False

postmark = PostmarkClient(server_token='d635b24a-e4ef-45c0-bab5-2afee7c71c57')
# mail = Mail(app)

# Database setup
db = SqliteDatabase('site.db')


class User(Model):
    username = CharField(unique=True)
    password = CharField()
    first_name = CharField()
    last_name = CharField()
    address = CharField()
    email = CharField()

    class Meta:
        database = db


class Listing(Model):
    title = CharField()
    description = CharField()
    starting_price = FloatField(constraints=[Check('starting_price >= 0')])
    image = BlobField()
    auction_duration = IntegerField(constraints=[Check('auction_duration >= 1 AND auction_duration <= 7')])
    end_time = DateTimeField()
    user = CharField()
    status = CharField()
    category = CharField()

    class Meta:
        database = db


class Bid(Model):
    title = CharField()
    asking_price = FloatField()
    bidding_user = CharField()
    listing_id = CharField()

    class Meta:
        database = db


# User model
# Initialize Flask-Admin
admin = Admin(app, name='Admin', template_mode='bootstrap3')
admin.add_view(ModelView(User))
admin.add_view(ModelView(Listing))
admin.add_view(ModelView(Bid))

# Initialize database
db.connect()
db.create_tables([User, Listing, Bid])


def send_generic_email(email, subject="genericSubject", body="genericBody"):
    response = postmark.emails.send(
        From='niloy.roy@torontomu.ca',  # for now
        To=email,
        Subject=subject,
        TextBody=body
    )
    if response['ErrorCode'] == 0:
        return 'SUCCESS'
    else:
        return f'Error sending email: {response["Message"]}'


def send_welcome_email(email):
    # test
    return send_generic_email(email,
                              subject='Welcome to Online Auction App',
                              body=f'🎉 Welcome to Online Auction App - Your Premier Online Auction Experience!\n\n'
                                   f' Dear Patron,\n\n'
                                   f' We are thrilled to welcome you to the Online Auction App family, your go-to destination for a thrilling online auction experience! Get ready to embark on a journey of discovery, excitement, and unbeatable deals right at your fingertips.\n\n'
                                   f'🚀 Why Online Auction App ?\n\n'
                                   f'✨ Curated Selections: Explore a handpicked collection of unique items that span from rare collectibles to everyday essentials, all waiting for your bid.\n\n'
                                   f'🔔 Real-Time Bidding: Experience the adrenaline rush as you participate in live auctions, engaging with other users in real-time. Stay one step ahead with our instant bid notifications.\n\n'
                                   f'💎 Secure Transactions: Bid with confidence! Our robust security measures ensure a safe and secure transaction environment, so you can focus on the thrill of the auction.\n\n'
                                   f'🌐 Global Marketplace: Join a community of bidders from around the world. Discover items from different corners of the globe and make your mark in the global auction scene.\n\n'
                                   f'🎁 Exclusive Offers: As a valued subscriber, enjoy exclusive access to early-bird auctions, special promotions, and insider perks that make your auction experience even more rewarding.\n\n'
                                   f'👋 Getting Started:\n\n'
                                   f'    Browse: Dive into our diverse categories and discover treasures waiting to find a new home.\n\n'
                                   f'    Bid: Place your bids strategically, and may the highest bid win!\n\n'
                                   f'    Win & Enjoy: Celebrate your victories and await the arrival of your new prized possessions.\n\n'
                                   f'📲 Stay Connected:\n\n'
                                   f'Follow us for the latest updates, auction highlights, and community stories. Have a question or need assistance? Our support team is ready to help.\n\n'
                                   f'Once again, welcome to Online Auction App! We can\'t wait for you to start bidding, winning, and enjoying the excitement of online auctions.\n\n'
                                   f'Happy Bidding!\n\n'
                                   f'Best Regards,\nThe Online Auction App Team 🌟')


def user_login(username, password):
    try:
        user = User.get(User.username == username)
        if check_password_hash(user.password, password):
            session['user'] = username
            session['login_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            session['user_info'] = {
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'address': user.address,
            }
            return True
    except User.DoesNotExist:
        return False


def create_user(username, password, first_name, last_name, address, email):
    hashed_password = generate_password_hash(password)
    try:
        with db.transaction():
            user = User.create(
                username=username,
                password=hashed_password,
                first_name=first_name,
                last_name=last_name,
                address=address,
                email=email
            )
            print(f'User created: {user.username} - {user.email}')
            send_welcome_email(email)
            return 'SUCCESS'
    except Exception as e:
        print(f'Error creating user: {str(e)}')
        return f'ERROR: {str(e)}'


def register_logout():
    if session.get('user') is not None:
        session.pop('user', None)
        session.pop('login_time', None)


def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))


def changePassword(username, newPassword=None):
    try:
        new_password = newPassword if (newPassword != None) else randomword(7)
        userObject = User.select().where(User.username == username).get()
        print(userObject, username)
        query = User.update(password=generate_password_hash(new_password)).where(User.username == username)
        query.execute()

        return True, {'userObject': userObject, 'username': username, 'newPassword': new_password}
    except Exception as e:
        print(e)

        return False, {'user': '', 'username': '', 'newPassword': ''}


def get_highest_bid(listing_id):
    try:
        highest_bid = (Bid
                       .select()
                       .where(Bid.listing_id == listing_id)
                       .order_by(Bid.asking_price.desc())
                       .get())
        print(highest_bid)
        return highest_bid
    except Bid.DoesNotExist:
        return None


def create_bid(product, bid_amount, user):
    try:
        with db.transaction():
            highest_bid = get_highest_bid(product.id)
            bid = Bid.create(
                title=product.title,
                asking_price=bid_amount,
                bidding_user=user,
                listing_id=product.id
            )
            return True
    except Exception as e:
        print(f'Error placing bid: {str(e)}')
        return False, f'Error placing bid: {str(e)}'


@app.route('/index')
@app.route('/')
def index():
    # print(changePassword('admin', 'admin')) # just in case 'admin' gets changed somehow
    return render_template('introPage.html', login_time=session.get('login_time'))


@app.route('/signin', methods=['POST', 'GET'])
def signin():
    # already logged in
    if session.get('user') is not None:
        return redirect(url_for('user', username=session['user']))

    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if user_login(username, password):
            return redirect(url_for('user', username=username))
        else:
            error = 'Invalid username/password'

    return render_template('signin.html', error=error)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        address = request.form['address']
        email = request.form['email']

        if User.select().where(User.email == email).exists():
            error = 'Email already exists'
        else:
            res = create_user(username, password, first_name, last_name, address, email)

            if res == 'SUCCESS':
                return render_template('signup.html', success=True), {"Refresh": "3; url=/signin"}
            else:
                error = res

    return render_template('signup.html', error=error)


@app.route('/user/<username>', methods=['GET', 'POST'])
def user(username):
    user = None
    sameUser = False

    if session.get('user') is not None and session.get('user') == username:
        # Assuming you store user info in the session during login
        user = session['user_info']
        sameUser = True

    try:
        user = User.get(User.username == username)
    except User.DoesNotExist:
        return redirect(url_for('index'))

    return render_template('userprofileloggedin.html', user=user, sameUser=sameUser)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if session.get('user') is not None:
        register_logout()
    return redirect(url_for('index'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        try:
            result, resultData = changePassword(username)
            if result == False:  # no second argument = random 7 letter password
                raise Exception('Could not change Password')
            forgotpassUser = resultData['userObject']
            new_password = resultData['newPassword']
            # forgotpassUser.update({'password' : new_password})
            print(f'User Password Updated: {forgotpassUser.username} - {forgotpassUser.email}')
            emailRes = send_generic_email(email=forgotpassUser.email,
                                          subject="Online Auction App forgot password",
                                          body=f"Your password for username {str(forgotpassUser.username)} is reset to {new_password}"
                                          )
            # check emailRes to see if sent?
            error = "Password sent to email"
        except Exception as e:
            error = "Invalid Username"
            print(e)
    return render_template('forgot_password.html', error=error)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    error = None
    if session.get('user') == None:  # only when logged in!
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = session.get('user')
        oldPassword = request.form['passwordOld']
        newPassword = request.form['passwordNew']
        newPasswordAgain = request.form['passwordNewAgain']
        try:
            userObject = User.select().where(User.username == username).get()
            if (oldPassword == '' or newPassword == '' or newPasswordAgain == ''):
                error = 'Password Fields cannot be Empty'
            elif check_password_hash(userObject.password, oldPassword) == False:
                error = "Old Password is incorrect"
            elif newPassword != newPasswordAgain:
                error = "New Passwords don't match!"
            elif newPassword == oldPassword:
                error = "New password must be different than old Password"
            else:
                result, resultData = changePassword(username, newPassword)
                if result == False:  # no second argument = random 7 letter password
                    error = 'Could not change Password'
                else:
                    error = "Password Successfully Changed"
        except Exception as e:
            error = "Invalid State or logged in user not in database"
            print(e)
    return render_template('change_password.html', error=error)


def calculate_timeleft(end_time, start_time):
    delta = end_time - start_time
    days, seconds = delta.days, delta.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60

app.jinja_env.filters['calculate_timeleft'] = calculate_timeleft


@app.route('/listing', methods=['POST', 'GET'])
def listing():
    listings = Listing.select()
    if request.method == 'POST':
        option = request.form["selectOption"]
        if (option == "Option 1"):
            listings = Listing.select().order_by(Listing.starting_price)
        elif (option == "Option 2"):
            listings = Listing.select().order_by(Listing.starting_price.desc())
        elif (option == "Option 3"):
            listings = Listing.select().order_by(Listing.end_time)
        elif (option == "Option 4"):
            listings = Listing.select().order_by(Listing.end_time.desc())
        elif (option == "Option 5"):
            listings = Listing.select().order_by(Listing.category.desc())
    current_datetime = datetime.now()

    return render_template('listing.html', listings=listings, current_datetime=current_datetime)


@app.route('/productListing/<product_id>', methods=['POST', 'GET'])
def productListing(product_id):
    error = None
    try:
        current_datetime = datetime.now()
        product = Listing.select().where(Listing.id == product_id).get()
        top_bid = get_highest_bid(product_id)
        if request.method == 'POST':
            if 'user' not in session:
                return redirect(url_for('signin'))
            user = session['user']
            bid_amount = float(request.form['bid-amount'])
            highest_bid = get_highest_bid(product.id)
            if user == product.user:
                error = 'Cannot make a bid for your own listing.'
                # return redirect(url_for('listing'))
            elif highest_bid is None or bid_amount > highest_bid.asking_price:
                if (bid_amount < product.starting_price):
                    error = ('Bidding Amount must be greater than starting price')
                    # return redirect(url_for('/productListing/' + product_id))
                else:
                    create_bid(product, bid_amount, user)
                    #redirect(url_for('listing'))
                    error = "Bid Created Successfully"
                    print("Bid successfully created")
            else:
                error = ('Bidding Amount must be greater than highest bid')
                # return redirect(url_for('/productListing/' + product_id))
            # return redirect(url_for('listing'))
        return render_template('productListing.html', product=product, top_bid=top_bid,
                               current_datetime=current_datetime, error=error)
    except Exception as e:  # error not found match, product id doesn't exist
        print(e)
    return redirect(url_for('listing'))  # not found page , redirect to listing for now


@app.route('/createListing', methods=['POST', 'GET'])
def createListing():
    if 'user' not in session:
        return redirect(url_for('signin'))
    error = None
    user = session['user']
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        starting_price = float(request.form['startingPrice'])
        duration = int(request.form['duration'])

        # Validate input
        if starting_price <= 0.01:
            error = ('Starting price must be greater than 0.01', 'error')
            # return redirect(url_for('createListing'))
        elif not (1 <= duration <= 7):
            error = ('Duration must be between 1 and 7 days', 'error')
            # return redirect(url_for('createListing'))

        if error == None and 'image' in request.files:
            image = request.files['image']
            filename = secure_filename(image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            filepath = filepath.replace('\\', '/')
            image.save(filepath)

        category = request.form['category']
        # Validate input
        if error == None and category not in ['electronics', 'household', 'clothing', 'everything_else']:
            error = ('Invalid category selected', 'error')
            # return redirect(url_for('createListing'))

        if error == None:  # no error yet
            try:
                with db.transaction():
                    current_time = datetime.now()
                    end_time = current_time + timedelta(days=duration)
                    listing = Listing.create(
                        title=title,
                        description=description,
                        starting_price=starting_price,
                        image=filepath if image else None,
                        auction_duration=duration,
                        end_time=end_time,
                        user=user,
                        status="Ongoing",
                        category=category
                    )
                    print(f'Listing created: {listing.title} - {listing.description}')
                    error = ('Listing Successfully Created', 'success')
                    # return redirect(url_for('createListing'))
            except Exception as e:
                print(f'Error creating listing: {str(e)}')
                error = (f'ERROR: {str(e)}', 'error')

    return render_template('createListing.html', error=error)


@app.route('/user_listings', methods=['GET'])
def user_listings():
    if session.get('user') is not None:
        try:
            username = session.get('user')
            user = User.get(User.username == username)
            listings = Listing.select().where(Listing.user == username)
            return render_template('myListing.html', username=username, listings=listings)
        except User.DoesNotExist:
            return render_template('userprofilenotfound.html')
    else:
        return redirect(url_for('signin'))


@app.route('/lostAuction')
def lostAuction():


    return render_template('lostAuction.html')


@app.route('/wonAuction')
def wonAuction():


    return render_template('wonAuction.html')

@app.route('/payment')
def payment():


    return render_template('payment-screen.html')

@app.route('/user_bids')
def user_bids():
    if session.get('user') is not None:
        try:
            username = session.get('user')
            bids = (Bid
                    .select(Bid, Listing)
                    .join(Listing, on=(Bid.listing_id == Listing.id))
                    .where(Bid.bidding_user == username))

            return render_template('myBids.html', username=username, bids=bids)
        except User.DoesNotExist:
            return render_template('userprofilenotfound.html')
    else:
        return redirect(url_for('signin'))


def get_listings_by_category(selected_category):
    if selected_category == 'All':
        return Listing.select()
    else:
        return Listing.select().where(Listing.category == selected_category.lower())


# Your existing routes..
#
# .

@app.route('/update_category', methods=['POST'])
def update_category():
    selected_category = request.get_json().get('category', 'All')
    filtered_listings = get_listings_by_category(selected_category)
    return render_template('listing_snippet.html', listings=filtered_listings)


def render_listing_snippet(selected_category):
    filtered_listings = get_listings_by_category(selected_category)
    return render_template('listing_snippet.html', listings=filtered_listings)


@app.route('/render_listing_snippet', methods=['POST'])
def render_listing_snippet_route():
    selected_category = request.get_json().get('category', 'All')
    return render_listing_snippet(selected_category)


@app.route('/selected_category', methods=['POST'])
def update_selected_category():
    selected_category = request.get_json().get('category', 'All')
    filtered_listings = get_listings_by_category(selected_category)
    return render_template('listing_snippet.html', listings=filtered_listings)



@app.route('/bid_status/<product_id>')
def bid_status(product_id):
    product = Listing.select().where(Listing.id == product_id).get()
    current_time = datetime.now()
    if product.end_time < current_time:
        highest_bid = get_highest_bid(product_id)
    if session['user'] == highest_bid.bidding_user:
        flash('You won the bid! Congrats!')
        redirect(url_for('wonAuction'))
        # render template for congrats page
            
    else: 
        flash('You lost the bid. Better luck next time!')
        # redirect to listing page (hopefully you will just see this message and be redirected to listing page?)
        redirect(url_for('lostAuction'))



if __name__ == '__main__':
    app.run(debug=True)
