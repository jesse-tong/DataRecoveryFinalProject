import os

# Mẫu đầu và cuối của ảnh JPG và PNG
JPG_HEADER = b'\xFF\xD8'
JPG_FOOTER = b'\xFF\xD9'
PNG_HEADER = b'\x89\x50\x4E\x47'
PNG_FOOTER = b'\xAE\x42\x60\x82'

def find_images_in_volume(image_file):
    with open(image_file, 'rb') as f:
        data = f.read()
    
    images = []

    # Tìm kiếm các ảnh JPG
    start = 0
    while start < len(data):
        # Tìm kiếm phần đầu của JPG
        start_jpg = data.find(JPG_HEADER, start)
        if start_jpg == -1:
            break

        # Tìm kiếm phần cuối của JPG
        end_jpg = data.find(JPG_FOOTER, start_jpg)
        if end_jpg == -1:
            break

        # Cắt ảnh JPG và lưu lại
        end_jpg += len(JPG_FOOTER)
        images.append(('image_{}.jpg'.format(len(images)+1), data[start_jpg:end_jpg]))

        # Tiếp tục tìm kiếm
        start = end_jpg

    # Tìm kiếm các ảnh PNG
    start = 0
    while start < len(data):
        # Tìm kiếm phần đầu của PNG
        start_png = data.find(PNG_HEADER, start)
        if start_png == -1:
            break

        # Tìm kiếm phần cuối của PNG
        end_png = data.find(PNG_FOOTER, start_png)
        if end_png == -1:
            break

        # Cắt ảnh PNG và lưu lại
        end_png += len(PNG_FOOTER)
        images.append(('image_{}.png'.format(len(images)+1), data[start_png:end_png]))

        # Tiếp tục tìm kiếm
        start = end_png

    return images

def save_images(images):
    for filename, image_data in images:
        with open(filename, 'wb') as img_file:
            img_file.write(image_data)
        print(f"Saved {filename}")

if __name__ == "__main__":
    image_file = 'Image00.Vol'  # Tên file chứa volume
    images = find_images_in_volume(image_file)
    if images:
        save_images(images)
    else:
        print("No images found.")