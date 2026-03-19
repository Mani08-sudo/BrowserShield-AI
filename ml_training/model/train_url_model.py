import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle

# load dataset
data = pd.read_csv("dataset/balanced_dataset.csv")

X = data["url"]
y = data["label"]

# convert text → numeric
vectorizer = TfidfVectorizer()

X_vec = vectorizer.fit_transform(X)

# split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_vec, y, test_size=0.2, random_state=42
)

# train model
model = RandomForestClassifier(n_estimators=100)

model.fit(X_train, y_train)

# test accuracy
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("Model accuracy:", accuracy)

# save model
pickle.dump(model, open("phishing_model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model saved successfully")