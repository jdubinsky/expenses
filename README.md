# expenses

Basic expenses tracking using flask, sqlite3, twitter bootstrap.

Features:
* Creation of users with username/password
* Change password
* One to many relationship of users; can have expenses between yourself and N users
* Add expense using plain english with a reason
* Automatic timestamp and timezone conversion of expenses
* Mark who answered the door (useful between my roommate and I for deliveries, let's us alternate between who gets the door)
* Delete an expense
* List all current expenses, order descending
* Quick view of your running total between other users

TODO:
* Improve UI
* Notify second party of deleted expense
* Paginated view of expenses
