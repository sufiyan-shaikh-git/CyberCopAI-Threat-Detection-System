import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# 1. Dataset load karein
df = pd.read_csv('malware_data.csv')
print("Dataset Loaded Successfully!")

# 2. Logic Adjustment: Malware 1 ko Legitimate 0 banana
# Isse aapka purana app.py bina kisi change ke chalega
df['legitimate'] = df['Malware'].apply(lambda x: 0 if x == 1 else 1)

# 3. Features select karein jo app.py extract karta hai
features = ['Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorSubsystemVersion', 
            'ImageBase', 'Subsystem', 'SectionMaxEntropy']

X = df[features]
y = df['legitimate']

# 4. Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 5. Model Training (Random Forest)
print("Training CyberCop's new brain...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 6. Accuracy Check
accuracy = model.score(X_test, y_test)
print(f"✅ Success! New Model Accuracy: {accuracy*100:.2f}%")

# 7. Save the Model and Features
joblib.dump(model, 'malware_model.pkl')
joblib.dump(features, 'model_features.pkl')
print("Final 'malware_model.pkl' is ready!")