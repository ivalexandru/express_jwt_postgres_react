create database jwttutorial_db;

--must set extension for uuid to work
create table users(user_id uuid primary key default uuid_generate_v4(), user_name varchar(255) not null, user_email varchar(255) not null, user_password varchar(255) );

--only SINGLE QUOTATIONS 
insert into users (user_name, user_email, user_password) values('hen', 'hen@gmail.com', 'hen12' );