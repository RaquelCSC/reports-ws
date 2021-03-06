CREATE DATABASE Report;
CREATE USER report WITH ENCRYPTED PASSWORD '39yYg7sFKhVRH2z3';
GRANT ALL PRIVILEGES ON DATABASE Report TO report;

DROP TABLE VisitorVisit;
DROP TABLE ProductVisit;
DROP TABLE Sell;
DROP TABLE Product;
DROP TABLE Visitor;

CREATE TABLE Visitor(
	id VARCHAR(255) PRIMARY KEY
);

CREATE TABLE VisitorVisit(
	id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
	date TIMESTAMP NOT NULL,
	durationSecs INT NOT NULL,
	isNew BOOL NOT NULL,
	host VARCHAR(1024) NOT NULL,
	visitorId VARCHAR(255) NOT NULL,
	FOREIGN KEY (visitorId) REFERENCES Visitor(id)
);

CREATE TABLE Product(
	id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
	name VARCHAR(255),
	activityType VARCHAR(255) NOT NULL
);

CREATE TABLE Sell(
	id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
	visitorId VARCHAR(255) NOT NULL,
	productId INT NOT NULL,
	date TIMESTAMP NOT NULL,
	value INT NOT NULL,
	FOREIGN KEY (visitorId) REFERENCES Visitor(id),
	FOREIGN KEY (productId) REFERENCES Product(id)
);

CREATE TABLE ProductVisit(
	id INT PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
	date TIMESTAMP NOT NULL,
	productId INT NOT NULL,
	FOREIGN KEY (productId) REFERENCES Product(id)
);

