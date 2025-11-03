export type Pretty<T> = {
  [K in keyof T]: T[K];
} & {};

export interface Typed {
  type: string;
}

export type PartialTyped<T extends Typed> = Pretty<Partial<T> & Pick<T, 'type'>>;
