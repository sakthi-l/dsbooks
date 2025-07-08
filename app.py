# app.py
import streamlit as st
import base64
import bcrypt
from pymongo import MongoClient
from datetime import datetime, time
import pandas as pd
import plotly.express as px
from bson import ObjectId
import socket
import gridfs
import re

# --- MongoDB Setup ---
db_password = st.secrets["mongodb"]["password"]  # Store in secrets.toml
mongo_uri = f"mongodb+srv://dsbook:{db_password}@cluster2.mqyyvj2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster2"
client = MongoClient(mongo_uri)
db = client["library"]
books_col = db["books"]
users_col = db["users"]
logs_col = db["logs"]
fav_col = db["favorites"]
fs = gridfs.GridFS(db)

# --- Utilities ---
def rerun(): st.rerun()
def safe_key(raw_key): return re.sub(r'[^a-zA-Z0-9_-]', '_', str(raw_key))
def get_ip():
    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except: return "unknown"
def dedupe_courses(default_list, db_list):
    seen, merged = set(), []
    for course in default_list + db_list:
        c = course.strip()
        if c.lower() not in seen:
            seen.add(c.lower())
            merged.append(c)
    return sorted(merged)

# --- Register/Login ---
def register_user():
    st.subheader("🌽 Register")
    username = st.text_input("Username", key="reg_username").strip().lower()
    password = st.text_input("Password", type="password", key="reg_password")
    if st.button("Register"):
        if users_col.find_one({"username": username}):
            st.error("Username already exists")
        else:
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            users_col.insert_one({
                "username": username,
                "password": hashed_pw,
                "verified": True,
                "created_at": datetime.utcnow()
            })
            st.success("Registered successfully")

def login_user():
    st.subheader("🔐 Login")
    username = st.text_input("Username", key="login_username").strip().lower()
    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        user = users_col.find_one({"username": username})
        if user and user.get("verified") and bcrypt.checkpw(password.encode(), bytes(user["password"])):
            st.session_state["user"] = username
            st.success(f"Welcome {username}")
            rerun()
        else:
            st.error("Invalid or unverified credentials")
def search_books():
    st.subheader("🔎 Search Books")

    with st.form("public_search_form"):
        with st.expander("🔧 Advanced Search Filters", expanded=True):
            title = st.text_input("Title")
            author = st.text_input("Author")
            keyword_input = st.text_input("Keywords (comma-separated)")

            languages = [l for l in books_col.distinct("language") if l and l.strip()]
            default_courses = [
                "Probability & Statistics using R", "Mathematics for Data Science",
                "Python for Data Science", "RDBMS,SQL & Visualization", "Data mining Techniques",
                "Artificial Intelligence and reasoning", "Machine Learning",
                "Big Data Mining and Analytics", "Predictive Analytics", "Ethics and Data Security",
                "Applied Spatial Data Analytics Using R", "Machine Vision",
                "Deep Learning & Applications", "Generative AI with LLMs",
                "Social Networks and Graph Analysis", "Data Visualization Techniques",
                "Algorithmic Trading", "Bayesian Data Analysis", "Healthcare Data Analytics",
                "Data Science for Structural Biology", "Other / Not Mapped"
            ]
            existing_courses = books_col.distinct("course")
            all_courses = dedupe_courses(default_courses, existing_courses)

            course_filter = st.selectbox("Course", ["All"] + all_courses)
            language_filter = st.selectbox("Language", ["All"] + sorted(languages))

        submitted = st.form_submit_button("🔍 Search")

    query = {}
    if title: query["title"] = {"$regex": title, "$options": "i"}
    if author: query["author"] = {"$regex": author, "$options": "i"}
    if keyword_input:
        keywords = [k.strip().lower() for k in keyword_input.split(",") if k.strip()]
        query["keywords"] = {"$in": keywords}
    if language_filter != "All": query["language"] = language_filter
    if course_filter != "All": query["course"] = course_filter

    books = list(books_col.find(query).sort("uploaded_at", -1).limit(50)) if submitted else []

    current_user = st.session_state.get("user", "guest")
    ip = get_ip()
    today_start = datetime.combine(datetime.utcnow().date(), time.min)

    for book in books:
        with st.expander(book["title"]):
            st.write(f"**Author:** {book.get('author', 'N/A')}")
            st.write(f"**Language:** {book.get('language', 'N/A')}")
            st.write(f"**Course:** {book.get('course', 'Not tagged')}")
            st.write(f"**Keywords:** {', '.join(book.get('keywords', []))}")

            file_id = book.get("file_id")
            if not file_id: continue

            try:
                if not isinstance(file_id, ObjectId):
                    file_id = ObjectId(file_id)
                grid_file = fs.get(file_id)
                data = grid_file.read()
                file_name = grid_file.filename

                allow_download = True if current_user != "guest" else not logs_col.find_one({
                    "user": "guest",
                    "ip": ip,
                    "type": "download",
                    "book": book["title"],
                    "timestamp": {"$gte": today_start}
                })

                session_key = f"public_logged_{book['_id']}"
                if allow_download:
                    st.download_button(
                        label="📥 Download PDF",
                        data=data,
                        file_name=file_name,
                        mime="application/pdf",
                        key=f"public_download_{safe_key(book['_id'])}"
                    )
                    if not st.session_state.get(session_key):
                        logs_col.insert_one({
                            "type": "download",
                            "user": current_user.lower(),
                            "ip": ip,
                            "book": book["title"],
                            "author": book.get("author"),
                            "language": book.get("language"),
                            "timestamp": datetime.utcnow()
                        })
                        st.session_state[session_key] = True
                else:
                    st.warning("🚫 Guests can download only 1 copy per day. Please login.")

            except Exception as e:
                st.error(f"❌ Could not retrieve file: {e}")

            # --- ⭐ Bookmark Feature ---
            if current_user != "guest":
                book_id_str = str(book["_id"])
                existing = fav_col.find_one({"user": current_user, "book_id": book_id_str})
                if existing:
                    if st.button("⭐ Remove Bookmark", key=f"remove_{book_id_str}"):
                        fav_col.delete_one({"_id": existing["_id"]})
                        st.success("Bookmark removed")
                        rerun()
                else:
                    if st.button("🌟 Add to Bookmarks", key=f"add_{book_id_str}"):
                        fav_col.insert_one({
                            "user": current_user,
                            "book_id": book_id_str,
                            "timestamp": datetime.utcnow()
                        })
                        st.success("Book bookmarked")
                        rerun()
def user_dashboard(user):
    import datetime
    import re

    def clean_text(text):
        if not isinstance(text, str): return text
        text = text.strip().lower()
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'[^\x20-\x7E]', '', text)
        return text

    st.subheader("📊 Your Dashboard")
    user = user.lower()

    logs = list(logs_col.find({"user": user, "type": "download"}))
    if logs:
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        selected_date = st.date_input("📆 Filter downloads by date", value=datetime.datetime.utcnow().date())
        df_filtered = df[df['timestamp'].dt.date == selected_date]

        df_filtered['book_clean'] = df_filtered['book'].apply(clean_text)
        df_filtered['author_clean'] = df_filtered['author'].apply(clean_text)
        df_filtered = df_filtered.drop_duplicates(subset=['book_clean', 'author_clean', 'language'])

        st.write(f"📥 Download History for {selected_date}")
        if not df_filtered.empty:
            st.dataframe(df_filtered[['book', 'author', 'language', 'timestamp']])
        else:
            st.info("No downloads found for this date.")
    else:
        st.info("You haven’t downloaded any books yet.")

    # --- Bookmarked Books ---
    st.write("⭐ **Bookmarked Books**")
    favs = list(fav_col.find({"user": user}))
    if favs:
        for f in favs:
            book = books_col.find_one({"_id": ObjectId(f["book_id"])})
            if book:
                with st.expander(f"📘 {book['title']}"):
                    st.write(f"**Author:** {book.get('author', 'N/A')}")
                    st.write(f"**Course:** {book.get('course', 'N/A')}")
                    st.write(f"**Language:** {book.get('language', 'N/A')}")
                    st.write(f"**Keywords:** {', '.join(book.get('keywords', []))}")
                    if st.button("❌ Remove Bookmark", key=f"dash_remove_{book['_id']}"):
                        fav_col.delete_one({"user": user, "book_id": str(book["_id"])})
                        st.success("Bookmark removed")
                        rerun()
    else:
        st.info("You haven’t bookmarked any books yet.")
def admin_dashboard():
    st.subheader("📊 Admin Analytics")

    total_views = logs_col.count_documents({})
    unique_downloads = logs_col.aggregate([
        {"$match": {"type": "download"}},
        {"$group": {
            "_id": {"user": "$user", "book": "$book", "date": {"$dateToString": {"format": "%Y-%m-%d", "date": "$timestamp"}}}
        }},
        {"$count": "count"}
    ])
    total_downloads = next(unique_downloads, {}).get("count", 0)

    st.metric("📈 Total Activity", total_views)
    st.metric("📥 Unique Downloads", total_downloads)

    logs = list(logs_col.find().sort("timestamp", -1))
    if logs:
        df = pd.DataFrame(logs)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        st.dataframe(df[['user', 'book', 'timestamp', 'type']])

    st.write("### 📚 Books Uploaded per Course")
    course_stats = books_col.aggregate([
        {"$group": {"_id": "$course", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ])
    course_data = [{"Course": row["_id"], "Count": row["count"]} for row in course_stats]
    if course_data:
        df = pd.DataFrame(course_data)
        st.dataframe(df)
        fig = px.bar(df, x="Course", y="Count", title="Books per Course")
        st.plotly_chart(fig)

def manage_users():
    st.subheader("👥 Manage Users")
    search_query = st.text_input("Search by username")
    query = {"username": {"$regex": search_query, "$options": "i"}} if search_query else {}
    users = list(users_col.find(query))

    if not users:
        st.info("No users found.")
        return

    for user in users:
        with st.expander(f"👤 {user['username']}"):
            st.write(f"✅ Verified: {'Yes' if user.get('verified') else 'No'}")
            st.write(f"🕒 Joined: {user.get('created_at', 'N/A')}")
            dl_count = logs_col.count_documents({"user": user["username"], "type": "download"})
            fav_count = fav_col.count_documents({"user": user["username"]})
            st.write(f"📥 Downloads: {dl_count}")
            st.write(f"⭐ Bookmarks: {fav_count}")

            logs = list(logs_col.find({"user": user["username"]}).sort("timestamp", -1))
            favs = list(fav_col.find({"user": user["username"]}))

            if logs:
                st.write("📄 Recent Downloads:")
                for l in logs[:5]:
                    st.write(f"- {l['book']} on {l['timestamp'].strftime('%Y-%m-%d')}")

            if favs:
                st.write("⭐ Bookmarked Books:")
                for f in favs:
                    book = books_col.find_one({"_id": ObjectId(f["book_id"])})
                    if book:
                        st.write(f"- {book['title']}")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("✅ Toggle Verified", key=f"verify_{safe_key(user['_id'])}"):
                    users_col.update_one(
                        {"_id": user["_id"]},
                        {"$set": {"verified": not user.get("verified", False)}}
                    )
                    st.success("Verification status updated")
                    rerun()

            with col2:
                delete_key = f"confirm_user_delete_{user['_id']}"
                if not st.session_state.get(delete_key):
                    if st.button("❌ Confirm Delete", key=f"delete_btn_{safe_key(user['_id'])}"):
                        if user["username"] == st.session_state.get("user"):
                            st.error("You cannot delete your own account while logged in.")
                        else:
                            st.session_state[delete_key] = True
                            st.warning("⚠️ Click again to permanently delete this user.")
                else:
                    if st.button("✅ Yes, Delete", key=f"final_user_delete_btn_{safe_key(user['_id'])}"):
                        users_col.delete_one({"_id": user["_id"]})
                        logs_col.delete_many({"user": user["username"]})
                        fav_col.delete_many({"user": user["username"]})
                        st.warning(f"✅ User '{user['username']}' deleted.")
                        del st.session_state[delete_key]
                        rerun()
def upload_book():
    st.subheader("📄 Upload Book")
    uploaded_file = st.file_uploader("Upload PDF", type="pdf")
    if uploaded_file:
        title = st.text_input("Title", value=uploaded_file.name.rsplit('.', 1)[0])
        author = st.text_input("Author")
        language = st.text_input("Language")
        keywords = st.text_input("Keywords (comma-separated)")

        default_courses = [  # 20 predefined from syllabus
            "Probability & Statistics using R", "Mathematics for Data Science",
            "Python for Data Science", "RDBMS,SQL & Visualization",
            "Data mining Techniques", "Artificial Intelligence and Reasoning",
            "Machine Learning", "Big Data Mining and Analytics",
            "Predictive Analytics", "Ethics and Data Security",
            "Applied Spatial Data Analytics Using R", "Machine Vision",
            "Deep Learning & Applications", "Generative AI with LLMs",
            "Social Networks and Graph Analysis", "Data Visualization Techniques",
            "Algorithmic Trading", "Bayesian Data Analysis",
            "Healthcare Data Analytics", "Data Science for Structural Biology",
            "Other / Not Mapped"
        ]
        existing_courses = books_col.distinct("course")
        course_options = dedupe_courses(default_courses, existing_courses)
        course = st.selectbox("Course", course_options)

        if st.button("Upload"):
            data = uploaded_file.read()
            file_id = fs.put(data, filename=uploaded_file.name)
            books_col.insert_one({
                "title": title,
                "author": author,
                "language": language,
                "course": course,
                "keywords": [k.strip().lower() for k in keywords.split(",")],
                "file_id": file_id,
                "file_name": uploaded_file.name,
                "uploaded_at": datetime.utcnow()
            })
            st.success("✅ Book uploaded successfully!")

def bulk_upload_with_gridfs():
    st.subheader("📥 Bulk Upload Books via CSV + PDF")
    st.markdown("CSV format: title, author, language, course, keywords, file_name")

    csv_file = st.file_uploader("Upload Metadata CSV", type="csv")
    pdf_files = st.file_uploader("Upload PDF Files", type="pdf", accept_multiple_files=True)

    if csv_file is None:
        st.warning("Please upload a CSV file to continue.")
        return

    df = pd.read_csv(csv_file)
    pdf_lookup = {f.name: f.read() for f in pdf_files} if pdf_files else {}
    count = 0

    for _, row in df.iterrows():
        file_name = row.get("file_name")
        file_data = pdf_lookup.get(file_name)
        if not file_data:
            st.warning(f"Skipping {row.get('title')} - PDF not found.")
            continue

        file_id = fs.put(file_data, filename=file_name)
        if books_col.find_one({"title": row.get("title", ""), "file_name": file_name}):
            continue

        books_col.insert_one({
            "title": row.get("title", ""),
            "author": row.get("author", ""),
            "language": row.get("language", ""),
            "course": row.get("course", ""),
            "keywords": [k.strip().lower() for k in str(row.get("keywords", "")).split(",")],
            "file_name": file_name,
            "file_id": file_id,
            "uploaded_at": datetime.utcnow()
        })
        count += 1

    st.success(f"✅ {count} book(s) uploaded.")

def edit_book_metadata():
    st.subheader("📝 Edit Book Metadata")
    books = list(books_col.find())
    if not books:
        st.warning("No books available.")
        return

    selected = st.selectbox("Select Book", [f"{b['title']} ({b.get('author', 'Unknown')})" for b in books])
    book = books[[f"{b['title']} ({b.get('author', 'Unknown')})" for b in books].index(selected)]

    title = st.text_input("Title", value=book["title"])
    author = st.text_input("Author", value=book.get("author", ""))
    language = st.text_input("Language", value=book.get("language", ""))
    keywords = st.text_input("Keywords", value=", ".join(book.get("keywords", [])))

    all_courses = dedupe_courses([
        "Probability & Statistics using R", "Mathematics for Data Science",
        "Python for Data Science", "RDBMS,SQL & Visualization", "Data mining Techniques",
        "Artificial Intelligence and reasoning", "Machine Learning", "Big Data Mining and Analytics",
        "Predictive Analytics", "Ethics and Data Security", "Applied Spatial Data Analytics Using R",
        "Machine Vision", "Deep Learning & Applications", "Generative AI with LLMs",
        "Social Networks and Graph Analysis", "Data Visualization Techniques",
        "Algorithmic Trading", "Bayesian Data Analysis", "Healthcare Data Analytics",
        "Data Science for Structural Biology", "Other / Not Mapped"
    ], books_col.distinct("course"))
    course = st.selectbox("Course", all_courses, index=all_courses.index(book.get("course", "Other / Not Mapped")))

    if st.button("Update Metadata"):
        books_col.update_one({"_id": book["_id"]}, {
            "$set": {
                "title": title.strip(),
                "author": author.strip(),
                "language": language.strip(),
                "keywords": [k.strip().lower() for k in keywords.split(",")],
                "course": course
            }
        })
        st.success("✅ Book metadata updated!")

def add_new_course():
    st.subheader("➕ Add New Course")
    new_course = st.text_input("Enter course name")
    if st.button("Add Course"):
        new_course = new_course.strip()
        if not new_course:
            st.warning("Course name cannot be empty.")
            return
        if new_course in books_col.distinct("course"):
            st.warning("Course already exists.")
        else:
            books_col.insert_one({
                "title": "[Dummy Course Entry]",
                "author": "",
                "language": "",
                "course": new_course,
                "keywords": [],
                "file_name": "",
                "file_id": "",
                "uploaded_at": datetime.utcnow()
            })
            st.success(f"✅ Course '{new_course}' added!")

def delete_book():
    st.subheader("🗑️ Delete Book")
    books = list(books_col.find().sort("uploaded_at", -1))
    if not books:
        st.info("No books available.")
        return

    selected = st.selectbox("Select Book", [f"{b['title']} ({b.get('author', 'Unknown')})" for b in books])
    book = books[[f"{b['title']} ({b.get('author', 'Unknown')})" for b in books].index(selected)]

    if st.button("❌ Confirm Delete"):
        try:
            fs.delete(ObjectId(book["file_id"]))
        except: pass
        books_col.delete_one({"_id": book["_id"]})
        logs_col.delete_many({"book": book["title"]})
        fav_col.delete_many({"book_id": str(book["_id"])})
        st.success("✅ Book deleted.")

def delete_course():
    st.subheader("🗑️ Delete Course")
    course = st.selectbox("Select Course", sorted(set(books_col.distinct("course"))))
    st.warning("⚠️ This will delete all books in this course.")
    if st.button("Delete Course"):
        confirm = st.checkbox("I confirm deletion of this course and its books")
        if confirm:
            books = list(books_col.find({"course": course}))
            for book in books:
                try:
                    if book.get("file_id"):
                        fs.delete(ObjectId(book["file_id"]))
                except: pass
                books_col.delete_one({"_id": book["_id"]})
                logs_col.delete_many({"book": book["title"]})
                fav_col.delete_many({"book_id": str(book["_id"])})
            st.success(f"✅ Deleted course '{course}' and {len(books)} books.")
            rerun()
def main():
    st.set_page_config("📚 DS Book Library")
    st.title("📚 DataScience E-Book Library")
    st.markdown("---")

    # --- Public search always visible ---
    search_books()
    st.markdown("---")

    # --- Sidebar login/register for guest ---
    if "user" not in st.session_state:
        with st.sidebar:
            choice = st.radio("Choose:", ["Login", "Register"])
            if choice == "Login":
                login_user()
            else:
                register_user()
        st.stop()

    # --- Authenticated User Flow ---
    user = st.session_state["user"]
    st.success(f"✅ Logged in as: {user}")
    admin_user = st.secrets["mongodb"]["admin_user"]
    admin_pass = st.secrets["mongodb"]["admin_pass"]

    if user == admin_user:
        with st.sidebar:
            pw = st.text_input("🔐 Admin Password", type="password")
            if pw != admin_pass:
                st.error("❌ Incorrect admin password")
                st.stop()

    if user == admin_user:
        st.sidebar.markdown("## 🔐 Admin Controls")
        admin_tab = st.sidebar.radio("🛠️ Admin Panel", [
            "📤 Upload Book",
            "📥 Bulk Upload",
            "📊 Analytics",
            "👥 Manage Users",
            "📝 Edit Book Metadata",
            "➕ Add Course",
            "🗑️ Delete Course",
            "🗑️ Delete Book",
            "⚠️ Clear Collections"
        ])

        if admin_tab == "📤 Upload Book":
            upload_book()
        elif admin_tab == "📥 Bulk Upload":
            bulk_upload_with_gridfs()
        elif admin_tab == "📊 Analytics":
            admin_dashboard()
        elif admin_tab == "👥 Manage Users":
            manage_users()
        elif admin_tab == "📝 Edit Book Metadata":
            edit_book_metadata()
        elif admin_tab == "➕ Add Course":
            add_new_course()
        elif admin_tab == "🗑️ Delete Course":
            delete_course()
        elif admin_tab == "🗑️ Delete Book":
            delete_book()
        elif admin_tab == "⚠️ Clear Collections":
            clear_collections()

    else:
        # --- For normal user ---
        user_dashboard(user)

    # --- Logout ---
    if st.button("🚪 Logout"):
        st.session_state.clear()
        st.rerun()

    # --- Footer prompt if somehow not logged ---
    if "user" not in st.session_state:
        st.markdown("---\n💡 **Login to access full features.**")

if __name__ == "__main__":
    main()
