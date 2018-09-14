import { BaseController } from './BaseController';
import { IUserRepository } from '../repositories/IUserRepository';
import { UserRepository } from '../repositories/UserRepository';
import { User, UserModel } from '../models/User';
import { Request, Response } from 'express';
import { sign } from 'jsonwebtoken';
import { compare } from 'bcryptjs';
import { Model } from 'mongoose';
/**
 * AWS
 */
import { AWSError, S3 } from 'aws-sdk';
import { coreConfig } from '../config/keys';
import { DeleteObjectOutput, DeleteObjectRequest } from 'aws-sdk/clients/s3';

export class UserController extends BaseController<User> {
  private readonly _userRepository: IUserRepository;
  readonly s3: S3;

  constructor(model: Model<User>) {
    super(model, 'user');
    this._userRepository = new UserRepository(model);
    this.s3 = new S3({
      accessKeyId: coreConfig.aws.accessKey,
      secretAccessKey: coreConfig.aws.secretKey,
    });
  }

  private deleteProfilePic(imageKey: string) {
    const params: DeleteObjectRequest = {
      Bucket: coreConfig.aws.bucketName,
      Key: imageKey,
    };

    this.s3.deleteObject(params, (err: AWSError, data: DeleteObjectOutput) => {
      if (err) console.log(err);
    });
  }

  register = async (req: Request, res: Response): Promise<Response> => {
    const { email, password } = req.body;

    try {
      const existedUser: User = await this._userRepository.getOne(email, 'email');

      if (existedUser) {
        return UserController.resolveErrorResponse(res, 400, 'Email exists');
      }

      const newUser: User = new UserModel({
        email,
        password,
      });

      const result: User = await this._userRepository.create(newUser);
      const savedUser: User = await result.save();

      const token: string = sign({ user: savedUser }, coreConfig.JWT.secret, { expiresIn: '7d' });
      return UserController.resolveResponse(res, 'Registration successfully', { token });
    } catch (e) {
      return UserController.resolveErrorResponse(res, 400, null, e);
    }
  }

  login = async (req: Request, res: Response): Promise<Response> => {
    const { email, password } = req.body;

    try {
      const fetched: User = await this._userRepository.getOne(email, 'email');

      if (!fetched || fetched === null) {
        return UserController.resolveErrorResponse(res, 400, 'Invalid Email/Password Combination');
      }

      const isMatched: boolean = await compare(password, fetched.password);

      if (!isMatched) {
        return UserController.resolveErrorResponse(res, 400, 'Invalid Email/Password Combination');
      }

      fetched.lastLogin = new Date();
      const result: User = await this._userRepository.update(fetched._id, fetched);
      delete result.password;

      const token: string = sign({ user: result }, coreConfig.JWT.secret, { expiresIn: '7d' });

      return UserController.resolveResponse(res, 'Login Successful', { token });
    } catch (e) {
      return UserController.resolveErrorResponse(res, 500, null, e);
    }
  }

  getProfile = async (req: Request, res: Response): Promise<Response> => {
    const currentUser: User = req['user'] as User;

    return UserController.resolveResponse(res, 'Profile retrieved successfully', {
      user: {
        email: currentUser.email,
        displayName: currentUser.displayName,
        imageURL: currentUser.imageURL,
        created: currentUser.created,
        lastLogin: currentUser.lastLogin,
      },
    });
  }

  uploadProfile = async (req: Request, res: Response): Promise<Response> => {
    try {
      const currentUser: User = await this._userRepository.getById((req['user'] as User)._id);
      const { displayName, password } = req.body;
      const file = req['file'] as S3File;

      if (displayName) {
        currentUser.displayName = displayName;
      }

      if (password) {
        currentUser.password = password;
      }

      if (file !== undefined) {
        if (currentUser.hasUploadedImage) {
          this.deleteProfilePic(currentUser.imageKey);
        }

        currentUser.imageURL = file.location;
        currentUser.imageKey = file.key;
        currentUser.hasUploadedImage = true;
      }

      await currentUser.save();
      return UserController.resolveResponse(res, 'Profile updated successfully');
    } catch (e) {
      return UserController.resolveErrorResponse(res, 500, null, e);
    }
  }

  resetProfilePic = async (req: Request, res: Response): Promise<Response> => {
    try {
      const currentUser: User = await this._userRepository.getById((req['user'] as User)._id);

      if (currentUser.hasUploadedImage) {
        this.deleteProfilePic(currentUser.imageKey);
      }

      currentUser.imageURL = req.body.imageURL;
      currentUser.imageKey = '';
      currentUser.hasUploadedImage = false;

      await currentUser.save();
      return UserController.resolveResponse(res, 'Profile updated successfully');
    } catch (e) {
      return UserController.resolveErrorResponse(res, 500, null, e);
    }
  }
}

export interface S3File {
  bucket: string;
  key: string;
  acl: string;
  contentType: string;
  contentDisposition: null;
  storageClass: string;
  serverSideEncryption: null;
  metadata: any;
  location: string;
  etag: string;
  /** Field name specified in the form */
  fieldname: string;
  /** Name of the file on the user's computer */
  originalname: string;
  /** Encoding type of the file */
  encoding: string;
  /** Mime type of the file */
  mimetype: string;
  /** Size of the file in bytes */
  size: number;
  /** The folder to which the file has been saved (DiskStorage) */
  destination: string;
  /** The name of the file within the destination (DiskStorage) */
  filename: string;
  /** Location of the uploaded file (DiskStorage) */
  path: string;
  /** A Buffer of the entire file (MemoryStorage) */
  buffer: Buffer;
}
