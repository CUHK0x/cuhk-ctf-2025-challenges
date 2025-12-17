export enum GadgetType {
  PARAGRAPH = "gadget.paragraph",
  TEXT_INPUT = "gadget.text_input",
  BUTTON = "gadget.button",
  IMAGE = "gadget.image",
  BOARD = "gadget.board",
}

export type BaseGadgetData = { id: string; left: number; top: number };

export type GadgetData = BaseGadgetData &
  (
    | { type: GadgetType.PARAGRAPH; content: string }
    | { type: GadgetType.TEXT_INPUT; placeholder: string }
    | { type: GadgetType.BUTTON; label: string }
    | { type: GadgetType.IMAGE; src: string; width: number; height: number }
    | { type: GadgetType.BOARD; board_id: string }
  );

export abstract class Gadget {
  public id!: string;
  public left!: number;
  public top!: number;
}

export class TextGadget extends Gadget {
  public content!: string;

  constructor(data: any) {
    super();
    Object.assign(this, data);
  }
}

export class InputGadget extends Gadget {
  public placeholder!: string;

  constructor(data: any) {
    super();
    Object.assign(this, data);
  }
}

export class ButtonGadget extends Gadget {
  public label!: string;

  constructor(data: any) {
    super();
    Object.assign(this, data);
  }
}

export class ImageGadget extends Gadget {
  public src!: string;
  public width!: number;
  public height!: number;

  constructor(data: any) {
    super();
    Object.assign(this, data);
  }
}

export class BoardGadget extends Gadget {
  public boardId!: string;

  constructor(data: any) {
    super();
    Object.assign(this, data);
  }
}
