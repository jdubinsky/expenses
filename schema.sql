CREATE TABLE Users (
	id INTEGER PRIMARY KEY ASC, 
	username TEXT, 
	password TEXT
);

CREATE TABLE Expenses (
	id INTEGER PRIMARY KEY ASC, 
	timestamp INTEGER,
	pair_id INTEGER,
	lessor_id INTEGER, 
	amount DECIMAL(10, 2),
	reason TEXT,
	FOREIGN KEY(lessor_id) REFERENCES Users(id),
	FOREIGN KEY(pair_id) REFERENCES UserPair(id)
);

Create Table Opened (
	id INTEGER PRIMARY KEY ASC,
	expense_id INTEGER,
	user_id INTEGER,
	FOREIGN KEY(expense_id) REFERENCES Expenses(id),
	FOREIGN KEY(user_id) REFERENCES Users(id)
);

Create Table RunningTotal (
	id INTEGER PRIMARY KEY ASC,
	pair_id INTEGER,
	debtor_id INTEGER,
	amount DECIMAL(10, 2),
	last_opened_id INTEGER,
	FOREIGN KEY(debtor_id) REFERENCES Users(id),
	FOREIGN KEY(last_opened_id) REFERENCES Opened(id),
	FOREIGN KEY(pair_id) REFERENCES UserPair(id)
);

Create Table UserPair (
	id INTEGER NOT NULL,
	user1 INTEGER NOT NULL,
	user2 INTEGER NOT NULL,
	FOREIGN KEY(user1) REFERENCES Users(id),
	FOREIGN KEY(user2) REFERENCES Users(id),
	UNIQUE(user1, user2)
);

CREATE INDEX idx_pair on Expenses (pair_id);
CREATE INDEX idx_expense on Opened (expense_id);
