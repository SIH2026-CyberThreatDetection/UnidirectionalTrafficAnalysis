def predict(model, features):
    prediction = model.predict(features)
    return {"threat_class": prediction[0]}

if __name__ == "__main__":
    print("Prediction interface initialized.")
