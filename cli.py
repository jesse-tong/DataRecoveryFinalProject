from file_operations import *
from otp import *
from make_smartOTP import *
import sys, os, datetime
from dateutil.parser import parse

fs = None
EXIT_CODE = 9
ERROR_CODE = 0

def cli():
    global fs # Gọi biến toàn cục fs
    print("1. Tạo/định dạng volume MyFS.Dat")
    print("2. Mở volume MyFS.Dat")
    print("3. Thiết lập/Đổi mật khẩu truy xuất MyFS")
    print("4. Liệt kê danh sách các tập tin trong MyFS")
    print("5. Thêm tập tin vào MyFS")
    print("6. Đặt/đổi mật khẩu truy xuất cho tập tin trong MyFS")
    print("7. Chép 1 tập tin trong MyFS ra ngoài")
    print("8. Xóa 1 tập tin trong MyFS")
    print("9. Thoát")
    choice = input("Chọn chức năng: ")
    if choice == '1':
        print("Tạo/định dạng volume MyFS.Dat")
        directory = input("Nhập vị trí tạo volume MyFS.Dat, mặc định thư mục hiện tại: ")
        if directory == "":
            directory = os.getcwd()
        elif not os.path.exists(directory):
            print("Thư mục không tồn tại")
            return ERROR_CODE
        fs = FileSystem(os.path.join(directory, "MyFS.dat"), metadata_path="metadata.dat")
        return 1
    elif choice == '2':
        print("Mở volume MyFS.Dat")
        directory = input("Nhập vị trí volume MyFS.Dat, mặc định thư mục hiện tại: ")
        if directory == "":
            directory = os.getcwd()
        elif not os.path.exists(directory):
            print("Volume không tồn tại")
            return ERROR_CODE
        fs = FileSystem(os.path.join(directory, "MyFS.dat"), metadata_path="metadata.dat")

        # Check volume's metadata and the current running machine to see if they match
        # If they don't match, the program will exit
        is_metadata_match = fs.compare_metadata()
        if not is_metadata_match:
            print("Metadata không khớp với máy hiện tại. Volume không thể mở")
            fs = None
            return ERROR_CODE

        return 2
    elif choice == '3':
        if fs == None:
            print("Volume MyFS chưa được mở, vui lòng mở/tạo volume bằng chức năng 1 hoặc 2")
            return ERROR_CODE
        print("Thiết lập/Đổi mật khẩu truy xuất MyFS")
        old_password = input("Nhập mật khẩu cũ: ")
        if not fs.is_password_match(old_password):
            print("Mật khẩu không đúng")
            return ERROR_CODE
        new_password = input("Nhập mật khẩu mới: ")
        fs.change_access_password(old_password=old_password, new_password=new_password)
        return 3
    elif choice == '4':
        if fs == None:
            print("Volume MyFS chưa được mở, vui lòng mở/tạo volume bằng chức năng 1 hoặc 2")
            return ERROR_CODE
        print("Liệt kê danh sách các tập tin trong MyFS")
        files = fs.list_files()
        print("List of files:")
        for index, file in enumerate(files, start=1):
            print(f"{index}. " + f"Tên tập tin trong MyFS: {file.filename}," + f" Kích thước ban đầu: {file.original_size} bytes," + 
                  f" Kích thước đã mã hóa: {file.encrypted_size} bytes, Ngày tạo: {parse(file.creation_date).strftime('%Y-%m-%d %H:%M:%S')}"
                  + f", Ngày sửa gần nhất: {parse(file.modification_date).strftime('%Y-%m-%d %H:%M:%S')}")
    elif choice == '5':
        if fs == None:
            print("Volume MyFS chưa được mở, vui lòng mở/tạo volume bằng chức năng 1 hoặc 2")
            return ERROR_CODE
        print("Thêm tập tin vào MyFS")
        filename = input("Nhập đường dẫn tập tin cần thêm vào MyFS: ")
        if not os.path.exists(filename):
            print("Tập tin không tồn tại")
            return ERROR_CODE
        filename_in_myfs = input("Nhập tên tập tin trong MyFS, tối đa 32 ký tự: ")
        file_password = input("Nhập mật khẩu truy xuất cho tập tin: ")
        fs.add_file(filename, filename_in_myfs, file_password)
    elif choice == '6':
        if fs == None:
            print("Volume MyFS chưa được mở, vui lòng mở/tạo volume bằng chức năng 1 hoặc 2")
            return ERROR_CODE
        print("Đặt/đổi mật khẩu truy xuất cho tập tin trong MyFS")
        filename_in_myfs = input("Nhập tên tập tin trong MyFS: ")

        old_file_password = input("Nhập mật khẩu truy xuất cho tập tin: ")
        new_file_password = input("Nhập mật khẩu mới: ")
        fs.reset_password(filename_in_myfs, old_file_password, new_file_password)
    elif choice == '7':
        if fs == None:
            print("Volume MyFS chưa được mở, vui lòng mở/tạo volume bằng chức năng 1 hoặc 2")
            return ERROR_CODE
        print("Chép 1 tập tin trong MyFS ra ngoài")
        filename_in_myfs = input("Nhập tên tập tin trong MyFS: ")
        filename = input("Nhập đường dẫn tập tin cần chép ra: ")
        file_password = input("Nhập mật khẩu truy xuất cho tập tin: ")
        fs.export_file(filename_in_myfs, filename, file_password)
    elif choice == '8':
        if fs == None:
            print("Volume MyFS chưa được mở, vui lòng mở/tạo volume bằng chức năng 1 hoặc 2")
            return ERROR_CODE
        print("Xóa 1 tập tin trong MyFS")
        filename_in_myfs = input("Nhập tên tập tin trong MyFS: ")
        fs.delete_file(filename_in_myfs)
    elif choice == '9':
        print("Thoát")
        return EXIT_CODE
    
def main_program():
    # Check user's OTP, if it is correct, the program will run; 
    # else if the user enter incorrect OTP 3 times, the program will exit
    for i in range(3):
        generated_X = generate_X()
        generated_OTP = make_smartOTP(generated_X)
        print(f"Giá trị X: {generated_X}")
        print(f"Giá trị OTP: {generated_OTP}. Bạn cũng có thể sử dụng chương trình make_smartOTP để lấy OTP từ X")
        OTP = input("Nhập OTP: ")
        if verify_OTP(OTP, generated_X, 60):
            break
        if i == 2:
            print("You have entered incorrect OTP 3 times. The program will exit")
            sys.exit()

    while True:
        result = cli()
        if result == EXIT_CODE:
            break
        elif result == ERROR_CODE:
            continue
    
if __name__ == '__main__':
    main_program()

    
    