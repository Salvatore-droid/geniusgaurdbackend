# test_groq_direct.py
import asyncio
from groq import AsyncGroq

async def test_groq():
    api_key = "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"
    
    try:
        client = AsyncGroq(api_key=api_key)
        
        completion = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "user", "content": "Say 'Groq is working!'"}
            ],
            temperature=0.1,
            max_tokens=50
        )
        
        print("✓ Groq API is working!")
        print(f"Response: {completion.choices[0].message.content}")
        return True
        
    except Exception as e:
        print(f"✗ Groq API error: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_groq())
    print(f"Test {'passed' if result else 'failed'}")