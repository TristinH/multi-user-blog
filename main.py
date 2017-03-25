#!/usr/bin/env python

import os
import webapp2
import jinja2
import re
import string
import random
import hashlib
import hmac
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# add secret here
s = ''


# secure a cookie
def secure(plain):
    return '%s|%s' % (plain, hmac.new(s, plain).hexdigest())


# verify a cookie
def verify_secure(test):
    plain = test.split('|')[0]
    if test == secure(plain):
        return plain


# create a random salt
def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in range(length))


# hash a password
def hash_string(name, password, salt=None):
    if not salt:
        salt = make_salt()
    hashed = hashlib.sha256(name + password + salt).hexdigest()
    return '%s,%s' % (hashed, salt)


# check a password
def check_hash(name, password, hashed):
    salt = hashed.split(',')[1]
    return hashed == hash_string(name, password, salt)


# main handler class with convenience functions
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # set a cookie in the browser
    def set_cookie(self, name, value):
        secure_cookie = secure(value)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, secure_cookie))

    # check for the cookie
    def get_cookie(self, name):
        cookie = self.request.cookies.get(name)
        return cookie and verify_secure(cookie)

    # log a user in
    def login(self, user):
        self.set_cookie('user', str(user.key().id()))

    # log a user out
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')

    # track user on different pages
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        u = self.get_cookie('user')
        self.user = u and User.by_id(int(u))


# class to store a single blog post
class BlogPost(db.Model):
    username = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=True)
    unlikes = db.IntegerProperty(required=True)

    # get the blogposts a user has submitted
    @classmethod
    def by_username(cls, username):
        return db.GqlQuery("SELECT * FROM BlogPost WHERE username = '%s'"
                           % username)


# class to keep track of likes to posts and users that like them
class LikePost(db.Model):
    username = db.StringProperty(required=True)
    post = db.IntegerProperty(required=True)

    # check if the user has already liked
    @classmethod
    def check_user_post(cls, username, post):
        results = db.GqlQuery("SELECT * FROM LikePost WHERE post=%s" +
                              "AND username=' % s'" % (post, username))
        if results.count() == 0:
            return False
        else:
            return True


# class to hold comments and their users
class Comment(db.Model):
    username = db.StringProperty(required=True)
    post = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)

    # get the comments for a certain post
    @classmethod
    def get_comments(cls, post):
        return db.GqlQuery("SELECT * FROM Comment WHERE post = %s" % post)


# class to store user information
class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, id):
        return User.get_by_id(id)

    @classmethod
    def by_name(cls, name):
        return User.all().filter('username =', name).get()

    @classmethod
    def register(cls, name, password, email=None):
        pw_hash = hash_string(name, password)
        u = User(username=name, password=pw_hash, email=email)
        return u

    @classmethod
    def login(cls, name, password):
        u = cls.by_name(name)
        if u and check_hash(name, password, u.password):
            return u


# handler for the main page
class MainPageHandler(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY" +
                            " created DESC LIMIT 10")
        error = self.request.get("error")
        # check if the user is signed in
        account = ""
        if self.user:
            # display logout link if signed in
            account = "Logout"
        else:
            # display sign in link if not signed in
            account = "Sign In"
        self.render("front.html", posts=posts, error=error, account=account)


# class to handle creating a new post
class NewPostHandler(Handler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/register?error=You must be" +
                          "signed in to create a post")

    def post(self):
        if not self.user:
            self.redirect("/signin")

        subject = self.request.get("subject")
        content = self.request.get("content")

        # check if the user entered both required fields
        if subject and content:
            # enter blog in database and redirect to individual blog page
            new_post = BlogPost(username=self.user.username, subject=subject,
                                content=content, likes=0, unlikes=0)
            new_post.put()
            self.redirect('/%s' % str(new_post.key().id()))
        else:
            error = "Post must have a subject and content"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


# handler for single posts
class SinglePostHandler(Handler):
    # find the individual blog post and display it on its own page
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/login")
        comments = Comment.get_comments(post_id)
        self.render("singlepost.html", post=post, comments=comments)


# handler for user registration
class RegistrationPageHandler(Handler):
    def get(self):
        error = self.request.get("error")
        self.render("registration.html", error=error)

    def post(self):
        bad_signup = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        # check to see if there are any registration errors
        error = ""
        if not username:
            error = "You must provide a username"
            bad_signup = True

        if not password:
            error = "You must provide a password"
            bad_signup = True
        elif not verify:
            error = "You must verify your password"
            bad_signup = True
        elif verify != password:
            error = "Passwords do not match"
            bad_signup = True

        if email and not re.match('.*@.*', email):
            error = "That is not a valid email"
            bad_signup = True

        # if there are errors reload the page with the error,
        # if not check if the user is already there
        if bad_signup:
            self.render("registration.html", error=error)
        else:
            u = User.by_name(username)
            if u:
                self.render("registration.html",
                            error="That username already taken")
            else:
                u = User.register(username, password, email)
                u.put()

                self.login(u)
                self.redirect("/welcome")


# handler for the welcome page
class WelcomePageHandler(Handler):
    def get(self):
        if self.user:
            # show the users the posts they have submitted
            user_posts = BlogPost.by_username(self.user.username)
            self.render("welcome.html", user_posts=user_posts,
                        username=self.user.username)
        else:
            self.redirect("/register")


# handler for user sign in
class SigninPageHandler(Handler):
    def get(self):
        self.render("signin.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect("/welcome")
        else:
            error = "Invalid login"
            self.render("signin.html", username=username, error=error)


# handler for user sign out
class LogoutPageHandler(Handler):
    def get(self):
        self.logout()
        self.redirect("/register")


# handler for editing a blog post
class EditPageHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        # make sure the user is the user of the post
        elif self.user.username != post.username:
            self.redirect("/register?error=You can only edit your own posts")
        else:
            self.render("editpost.html", user=self.user.username,
                        subject=post.subject, content=post.content)

    def post(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        # make sure the user is the user of the post
        elif self.user.username != post.username:
            self.redirect("/register?error=You can only edit your own posts")
        else:
            subject = self.request.get("subject")
            content = self.request.get("content")

            # check if the user entered both required fields
            if subject and content:
                # update the entry in the database
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/%s' % str(post.key().id()))
            else:
                error = "Post must have a subject and content"
                self.render("newpost.html", subject=subject, content=content,
                            error=error)


# handler to delete a post
class DeletePageHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        # check if the user is the post user
        elif self.user.username != post.username:
            self.redirect("/register?error=You can only delete your own posts")
        else:
            post.delete()
            time.sleep(0.5)
            self.redirect("/")


# handler to like a post
class LikePageHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        # make sure user is not liking own post, signed in,
        # and hasn't already liked it
        elif not self.user:
            self.redirect("/register?error=You must " +
                          "be signed in to like/unlike posts")
        elif self.user.username == post.username:
            self.redirect("/?error=You cannot like/unlike your own posts")
        elif LikePost.check_user_post(self.user.username, int(post_id)):
            self.redirect("/?error=You can only like/unlike a post once")
        else:
            post.likes += 1
            post.put()
            new_like = LikePost(username=self.user.username, post=int(post_id))
            new_like.put()
            self.redirect("/")


# handler for the unlike of a post
class UnlikePageHandler(Handler):
    # same logic as handling a like
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/register?error=You must be " +
                          "signed in to like/unlike posts")
        elif self.user.username == post.username:
            self.redirect("/?error=You cannot like/unlike your own posts")
        elif LikePost.check_user_post(self.user.username, int(post_id)):
            self.redirect("/?error=You can only like/unlike a post once")
        else:
            post.unlikes += 1
            post.put()
            new_like = LikePost(username=self.user.username, post=int(post_id))
            new_like.put()
            self.redirect("/")


# handler for creating a comment
class CommentPageHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        # make sure user is signed in
        elif not self.user:
            self.redirect("/register?error=You must be " +
                          "signed in to comment on posts")
        else:
            self.render("commentform.html", subject=post.subject,
                        content=post.content)

    def post(self, post_id):
        comment = self.request.get('comment')
        key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(key)
        if not post:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        # make sure the user actually enters a comment
        elif not comment:
            error = "You must type something into the comment"
            self.render("commentform.html", subject=post.subject,
                        content=post.content, error=error)
        else:
            new_comment = Comment(username=self.user.username,
                                  post=int(post_id), comment=comment)
            new_comment.put()
            time.sleep(0.5)
            self.redirect('/%s' % int(post_id))


# handler for editing a comment
class CommentEditHandler(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        elif comment.username != self.user.username:
            self.redirect("/register?error=You can only edit " +
                          "your own comments")
        else:
            self.render("editcomment.html", comment=comment.comment)

    def post(self, comment_id):
        comment_text = self.request.get('comment')
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        elif not comment_text:
            error = "You must type something into the comment"
            self.render("commentform.html", comment=comment.comment,
                        error=error)
        else:
            comment.comment = comment_text
            comment.put()
            time.sleep(0.5)
            self.redirect('/%s' % int(comment.post))


# handler for deleting a comment
class CommentDeleteHandler(Handler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not comment:
            self.redirect("/signin")
        elif not self.user:
            self.redirect("/signin")
        elif comment.username != self.user.username:
            self.redirect("/register?error=You can only " +
                          "delete your own comments")
        else:
            comment.delete()
            time.sleep(0.5)
            self.redirect('/%s' % int(comment.post))

app = webapp2.WSGIApplication([
    ('/', MainPageHandler),
    ('/newpost', NewPostHandler),
    ('/([0-9]+)', SinglePostHandler),
    ('/register', RegistrationPageHandler),
    ('/welcome', WelcomePageHandler),
    ('/signin', SigninPageHandler),
    ('/logout', LogoutPageHandler),
    ('/edit/([0-9]+)', EditPageHandler),
    ('/delete/([0-9]+)', DeletePageHandler),
    ('/like/([0-9]+)', LikePageHandler),
    ('/unlike/([0-9]+)', UnlikePageHandler),
    ('/comment/([0-9]+)', CommentPageHandler),
    ('/commentedit/([0-9]+)', CommentEditHandler),
    ('/commentdelete/([0-9]+)', CommentDeleteHandler)
], debug=True)
