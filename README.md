# Online Learning Platform


A full-stack **Online Learning Platform** inspired by Utkarsh App, designed for students, instructors, and admins. This platform supports course management, lessons, quizzes, live classes, progress tracking, notifications, and certificates.

---

## **Table of Contents**
- [Features](#features)
- [Roles](#roles)
- [Modules](#modules)
- [Tech Stack](#tech-stack)
- [Database Schema](#database-schema)
- [Folder Structure](#folder-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Future Enhancements](#future-enhancements)
- [License](#license)

---

## **Features**
- User Authentication (Signup/Login)
- Role-based access: Admin, Instructor, Student
- Browse and enroll in free or paid courses
- Course content: video lessons, PDFs, quizzes
- Progress tracking and completion percentage
- Live classes with real-time video streaming and chat
- Push/email notifications
- Certificates generation for course completion
- Admin dashboard for analytics and user management

---

## **Roles**
1. **Admin**
   - Manage users, courses, live classes
   - View payments, analytics
   - Send notifications

2. **Instructor**
   - Add & manage courses
   - Upload lessons, quizzes
   - Conduct live classes
   - Track student progress

3. **Student**
   - Browse & enroll in courses
   - Access lessons & quizzes
   - Attend live classes
   - Track progress and earn certificates

---

## **Modules**
- **Authentication Module**: Login, Signup, JWT sessions
- **User Management Module**: Admin manages users
- **Course Management Module**: CRUD courses & lessons
- **Lesson Module**: Video/PDF delivery, progress tracking
- **Enrollment & Payment Module**: Free & paid courses
- **Quiz Module**: Add & attempt quizzes
- **Progress Tracking Module**: Track lessons & quiz scores
- **Live Class Module**: Real-time classes with chat
- **Notification Module**: Alerts & reminders
- **Certificate Module**: Generate PDF certificates
- **Analytics Module**: Reports & insights for Admin

---

## **Tech Stack**
- **Backend:** Node.js, Express.js
- **Frontend:** React.js
- **Database:** MongoDB
- **Authentication:** JWT, Bcrypt
- **Real-Time Communication:** WebRTC / Agora / Socket.IO
- **Cloud Storage:** AWS S3 / Firebase Storage (for videos/PDFs)
- **Payment Gateway:** Razorpay / Stripe

---

## **Database Schema**
- `users` → user info, role, progress
- `courses` → course details, lessons, quizzes
- `lessons` → video/pdf links, order
- `quizzes` → questions & answers
- `enrollments` → tracks which student enrolled
- `live_classes` → scheduled/live/completed sessions
- `notifications` → alerts & messages
- `certificates` → course completion certificates

---

