import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load dataset
df = pd.read_csv('packets_dataset.csv')

# Basic feature encoding
df['proto'] = df['proto'].map({'TCP':1, 'UDP':2, 'IP':3})

# TEMP label creation for demo
# Later you manually label (normal/suspicious)
df['label'] = 0  # mark all normal for now

X = df[['size','proto','sport','dport','ttl']]
y = df['label']

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, 'packet_model.pkl')

print("Model saved as packet_model.pkl")
